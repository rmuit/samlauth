<?php

namespace Drupal\samlauth;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Url;
use Drupal\externalauth\ExternalAuth;
use Drupal\samlauth\Event\SamlauthEvents;
use Drupal\samlauth\Event\SamlauthUserSyncEvent;
use Drupal\user\UserInterface;
use Exception;
use InvalidArgumentException;
use OneLogin_Saml2_Auth;
use OneLogin_Saml2_Error;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * Governs communication between the SAML toolkit and the IDP / login behavior.
 */
class SamlService {

  /**
   * A OneLogin_Saml2_Auth object representing the current request state.
   *
   * @var \OneLogin_Saml2_Auth
   */
  protected $samlAuth;

  /**
   * The ExternalAuth service.
   *
   * @var \Drupal\externalauth\ExternalAuth
   */
  protected $externalAuth;

  /**
   * A configuration object containing samlauth settings.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * The EntityTypeManager service.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * A logger instance.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * The event dispatcher.
   *
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  protected $eventDispatcher;

  /**
   * Constructor for Drupal\samlauth\SamlService.
   *
   * @param \Drupal\externalauth\ExternalAuth $external_auth
   *   The ExternalAuth service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The EntityTypeManager service.
   * @param \Psr\Log\LoggerInterface $logger
   *   A logger instance.
   * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $event_dispatcher
   *   The event dispatcher.
   */
  public function __construct(ExternalAuth $external_auth, ConfigFactoryInterface $config_factory, EntityTypeManagerInterface $entity_type_manager, LoggerInterface $logger, EventDispatcherInterface $event_dispatcher) {
    $this->externalAuth = $external_auth;
    $this->config = $config_factory->get('samlauth.authentication');
    $this->entityTypeManager = $entity_type_manager;
    $this->logger = $logger;
    $this->eventDispatcher = $event_dispatcher;
    $this->samlAuth = new OneLogin_Saml2_Auth(static::reformatConfig($this->config));
  }

  /**
   * Returns the route name that users will be redirected to after authenticating.
   *
   * @return string
   * @todo make this configurable
   */
  public function getPostLoginDestination() {
    return 'user.page';
  }

  /**
   * Returns the route name that users will be redirected to after logging out.
   *
   * @return string
   * @todo make this configurable
   */
  public function getPostLogoutDestination() {
    return '<front>';
  }

  /**
   * Show metadata about the local sp. Use this to configure your saml2 IDP
   *
   * @return mixed xml string representing metadata
   * @throws InvalidArgumentException
   */
  public function getMetadata() {
    $settings = $this->samlAuth->getSettings();
    $metadata = $settings->getSPMetadata();
    $errors = $settings->validateMetadata($metadata);

    if (empty($errors)) {
      return $metadata;
    }
    else {
      throw new InvalidArgumentException(
        'Invalid SP metadata: ' . implode(', ', $errors),
        OneLogin_Saml2_Error::METADATA_SP_INVALID
      );
    }
  }

  /**
   * Initiates a SAML2 authentication flow and redirects to the IDP.
   *
   * @param string $return_to
   *   (optional) The path to return the user to after successful processing by
   *   the IDP. The SP's AssertionConsumerService path is used by default.
   */
  public function login($return_to = null) {
    if (!$return_to) {
      $sp_config = $this->samlAuth->getSettings()->getSPData();
      $return_to = $sp_config['assertionConsumerService']['url'];
    }
    $this->samlAuth->login($return_to);
  }

  /**
   * Initiates a SAML2 logout flow and redirects to the IdP.
   *
   * @param null $return_to
   *   (optional) The path to return the user to after successful processing by
   *   the IDP. The SP's SingleLogoutService path is used by default.
   */
  public function logout($return_to = null) {
    if (!$return_to) {
      $sp_config = $this->samlAuth->getSettings()->getSPData();
      $return_to = $sp_config['singleLogoutService']['url'];
    }
    user_logout();
    $this->samlAuth->logout($return_to, array('referrer' => $return_to));
  }

  /**
   * Processes a SAML response (Assertion Consumer Service).
   *
   * First checks whether the SAML request is OK, then takes action on the
   * Drupal user (logs in / maps existing / create new) depending on attributes
   * sent in the request and our module configuration.
   *
   * @throws Exception
   */
  public function acs() {
    // This call can either set an error condition or throw a
    // \OneLogin_Saml2_Error exception, depending on whether or not we are
    // processing a POST request. Don't catch the exception.
    $this->samlAuth->processResponse();
    // Now look if there were any errors and also throw.
    $errors = $this->samlAuth->getErrors();
    if (!empty($errors)) {
      // We have one or multiple error types / short descriptions, and one
      // 'reason' for the last error.
      throw new Exception('Error(s) encountered during processing of ACS response. Type(s): ' . implode(', ', array_unique($errors)) . '; reason given for last error: ' . $this->samlAuth->getLastErrorReason());
    }

    if (!$this->isAuthenticated()) {
      throw new Exception('Could not authenticate.');
    }

    $unique_id = $this->getAttributeByConfig('unique_id_attribute');
    if (!$unique_id) {
      throw new Exception('Configured unique ID is not present in SAML response.');
    }

    $account = $this->externalAuth->load($unique_id, 'samlauth');
    if (!$account) {
      $this->logger->debug('No matching local users found for unique SAML ID @saml_id.', array('@saml_id' => $unique_id));

      // @todo use the regular mail attribute config for this?
      $map_mail = $this->getAttributeByConfig('map_users_email');
      if ($this->config->get('map_users') && $map_mail
          && $account_search = $this->entityTypeManager->getStorage('user')->loadByProperties(array('mail' => $map_mail))) {
        $account = reset($account_search);
        $this->logger->info('Matching local user @uid found for e-mail @mail in SAML data; associating user and logging in.', array('@mail' => $map_mail, '@uid' => $account->id()));
        // An existing 'samlauth' link for the account will be overwritten.
        $this->externalAuth->linkExistingAccount($unique_id, 'samlauth', $account);
        $this->externalAuth->userLoginFinalize($account, $unique_id, 'samlauth');
      }

      // @todo: we should first try to link existing accounts by _user_ too;
      //        externalauth will throw an exception if an account with the same
      //        name exists and we are doing nothing to prevent that.
      elseif ($this->config->get('create_users')) {
        // The register() call will save the account. We want to:
        // - add values from the SAML response into the user account;
        // - not save the account twice (because if the second save fails we do
        //   not want to end up with a user account in an undetermined state);
        // - reuse code (i.e. call synchronizeUserAttributes() with its current
        //   signature, which is also done when an existing user logs in).
        // Because of the third point, we are not passing the necessary SAML
        // attributes into register()'s $account_data parameter, but we want to
        // hook into the save operation of the user account object that is
        // created by register(). It seems we can only do this by implementing
        // hook_user_presave() - which calls our synchronizeUserAttributes().
        $account = $this->externalAuth->register($unique_id, 'samlauth');

        $this->externalAuth->userLoginFinalize($account, $unique_id, 'samlauth');
      }
      else {
        throw new Exception('No existing user account matches the SAML ID provided. This authentication service is not configured to create new accounts.');
      }
    }
    elseif ($account->isBlocked()) {
      throw new Exception('Requested account is blocked.');
    }
    else {
      // Synchronize the user account with SAML attributes if needed.
      $this->synchronizeUserAttributes($account);

      $this->externalAuth->userLoginFinalize($account, $unique_id, 'samlauth');
    }
  }

  /**
   * Does processing for the Single Logout Service if necessary.
   */
  public function sls() {
    // @todo change; see SamlController::sls().
    user_logout();
  }

  /**
   * Synchronizes user data with attributes in the SAML request.
   *
   * Currently does not actually sync attributes on login because no "sync"
   * settings are implemented yet. (Note syncing-on-login is not the same as
   * 'map users'.) This at least is a first step to implementing it though.
   * Currently this is only called for adding user data from SAML attributes
   * into new accounts before saving, and not all checks are actually necessary
   * yet.
   *
   * Code borrowed from simplesamlphp_auth module with thanks & the intention to
   * keep code bases similar where that makes sense.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user to synchronize attributes into.
   */
  public function synchronizeUserAttributes(UserInterface $account) {
    $sync_mail = $account->isNew(); //  || $this->config->get('sync.mail');
    $sync_user_name = $account->isNew(); // || $this->config->get('sync.user_name');
    $save = FALSE;

    if ($sync_user_name) {
      $name = $this->getAttributeByConfig('user_name_attribute');
      if ($name) {
        $existing = FALSE;
        $account_search = $this->entityTypeManager->getStorage('user')->loadByProperties(array('name' => $name));
        if ($existing_account = reset($account_search)) {
          if ($account->id() != $existing_account->id()) {
            $existing = TRUE;
            $this->logger->critical("Error on synchronizing name attribute: an account with the username %username already exists.", ['%username' => $name]);
            drupal_set_message(t('Error synchronizing username: an account with this username already exists.'), 'error');
          }
        }

        if (!$existing && $name !== $account->getAccountName()) {
          $account->setUsername($name);
          $save = TRUE;
        }
      }
      else {
        $this->logger->critical("Error on synchronizing name attribute: no username available for Drupal user %id.", ['%id' => $account->id()]);
        drupal_set_message(t('Error synchronizing username: no username is provided by SAML.'), 'error');
      }
    }

    if ($sync_mail) {
      $mail = $this->getAttributeByConfig('user_mail_attribute');
      if ($mail && $mail !== $account->getEmail()) {
        $account->setEmail($mail);
        if ($account->isNew()) {
          // externalauth sets 'init' to a non e-mail value so we will fix it.
          $account->set('init', $mail);
        }
        $save = TRUE;
      }
      else {
        $this->logger->critical("Error on synchronizing mail attribute: no email address available for Drupal user %id.", ['%id' => $account->id()]);
        drupal_set_message(t('Error synchronizing mail: no email address is provided by SAML.'), 'error');
      }
    }

    // Dispatch a user_sync event.
    $event = new SamlauthUserSyncEvent($account, $this->getAttributes());
    $this->eventDispatcher->dispatch(SamlauthEvents::USER_SYNC, $event);

    // Save the account if we changed attributes earlier on, but never if the
    // account is new because then we're in the middle of a save operation.
    if (($save || $event->isAccountChanged()) && !$account->isNew()) {
      $account->save();
    }
  }

  /**
   * Returns all attributes in a SAML response.
   *
   * @return array
   *   An array with all returned SAML attributes..
   */
  public function getAttributes() {
    return $this->samlAuth->getAttributes();
  }

  /**
   * Returns an attribute value in a SAML response. This method will return
   * valid data after a response is processed (i.e. after acs() was called).
   *
   * @param string
   *   A key in the module's configuration, containing the name of a SAML
   *   attribute.
   *
   * @return mixed|null
   *   The SAML attribute value; NULL if the attribute value, or configuration
   *   key, was not found.
   */
  public function getAttributeByConfig($config_key) {
    $attribute_name = $this->config->get($config_key);
    if ($attribute_name) {
      $attribute = $this->samlAuth->getAttribute($attribute_name);
      if (!empty($attribute[0])) {
        return $attribute[0];
      }
    }
  }

  /**
   * @return bool if a valid user was fetched from the saml assertion this request.
   */
  protected function isAuthenticated() {
    return $this->samlAuth->isAuthenticated();
  }

  /**
   * Returns a configuration array as used by the external library.
   *
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The module configuration.
   *
   * @return array
   *   The library configuration array.
   */
  protected static function reformatConfig(ImmutableConfig $config) {
    // Check if we want to load the certificates from a folder. Either folder or
    // cert+key settings should be defined. If both are defined, "folder" is the
    // preferred method and we ignore cert/path values; we don't do more
    // complicated validation like checking whether the cert/key files exist.
    $sp_cert = '';
    $sp_key = '';
    $cert_folder = $config->get('sp_cert_folder');
    if ($cert_folder) {
      // Set the folder so the Simple SAML toolkit knows where to look.
      define('ONELOGIN_CUSTOMPATH', "$cert_folder/");
    }
    else {
      $sp_cert = $config->get('sp_x509_certificate');
      $sp_key = $config->get('sp_private_key');
    }

    return array(
      'sp' => array(
        'entityId' => $config->get('sp_entity_id'),
        'assertionConsumerService' => array(
          'url' => Url::fromRoute('samlauth.saml_controller_acs', array(), array('absolute' => TRUE))->toString(),
        ),
        'singleLogoutService' => array(
          'url' => Url::fromRoute('samlauth.saml_controller_sls', array(), array('absolute' => TRUE))->toString(),
        ),
        'NameIDFormat' => $config->get('sp_name_id_format'),
        'x509cert' => $sp_cert,
        'privateKey' => $sp_key,
      ),
      'idp' => array (
        'entityId' => $config->get('idp_entity_id'),
        'singleSignOnService' => array (
          'url' => $config->get('idp_single_sign_on_service'),
        ),
        'singleLogoutService' => array (
          'url' => $config->get('idp_single_log_out_service'),
        ),
        'x509cert' => $config->get('idp_x509_certificate'),
      ),
      'security' => array(
        'authnRequestsSigned' => $config->get('security_authn_requests_sign') ? TRUE : FALSE,
        'wantMessagesSigned' => $config->get('security_messages_sign') ? TRUE : FALSE,
        'wantNameIdSigned' => $config->get('security_name_id_sign') ? TRUE : FALSE,
        'requestedAuthnContext' => $config->get('security_request_authn_context') ? TRUE : FALSE,
      ),
    );
  }

}
