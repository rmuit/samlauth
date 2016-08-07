<?php

/**
 * @file
 * Contains Drupal\samlauth\SamlService.
 */

namespace Drupal\samlauth;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Url;
use Drupal\user\UserInterface;
use InvalidArgumentException;
use OneLogin_Saml2_Auth;
use OneLogin_Saml2_Error;
use Psr\Log\LoggerInterface;

/**
 * Class SamlService.
 *
 * @package Drupal\samlauth
 */
class SamlService {

  /**
   * A OneLogin_Saml2_Auth object representing the current request state.
   *
   * @var \OneLogin_Saml2_Auth
   */
  protected $auth;

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
   * Constructor for Drupal\samlauth\SamlService.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The EntityTypeManager service.
   * @param \Psr\Log\LoggerInterface $logger
   *   A logger instance.
   */
  public function __construct(ConfigFactoryInterface $config_factory, EntityTypeManagerInterface $entity_type_manager, LoggerInterface $logger) {
    $this->config = $config_factory->get('samlauth.authentication');
    $this->entityTypeManager = $entity_type_manager;
    $this->logger = $logger;
    $this->auth = new OneLogin_Saml2_Auth(static::reformatConfig($this->config));
  }

  /**
   * Show metadata about the local sp. Use this to configure your saml2 IDP
   *
   * @return mixed xml string representing metadata
   * @throws InvalidArgumentException
   */
  public function getMetadata() {
    $settings = $this->auth->getSettings();
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
      $sp_config = $this->auth->getSettings()->getSPData();
      $return_to = $sp_config['assertionConsumerService']['url'];
    }
    $this->auth->login($return_to);
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
      $sp_config = $this->auth->getSettings()->getSPData();
      $return_to = $sp_config['singleLogoutService']['url'];
    }
    user_logout();
    $this->auth->logout($return_to, array('referrer' => $return_to));
  }

  /**
   * Processes a SAML response (Assertion Consumer Service).
   *
   * @return array|null
   *   Returns array with error description on error. Null otherwise.
   * @throws \OneLogin_Saml2_Error
   */
  public function acs() {
    $this->auth->processResponse();
    $errors = $this->auth->getErrors();

    if (!empty($errors)) {
      return $errors;
    }

    if (!$this->isAuthenticated()) {
      return array('error' => 'Could not authenticate.');
    }
  }

  /**
   * Does processing for the Single Logout Service if necessary.
   */
  public function sls() {
    // @todo we already called user_logout() at the start of the logout
    // procedure i.e. at logout(). The route that leads here is only accessible
    // for authenticated user. So will this never be executed and should we
    // change this code?
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

        if (!$existing) {
          $account->setUsername($name);
        }
      }
      else {
        $this->logger->critical("Error on synchronizing name attribute: no username available for Drupal user %id.", ['%id' => $account->id()]);
        drupal_set_message(t('Error synchronizing username: no username is provided by SAML.'), 'error');
      }
    }

    if ($sync_mail) {
      $mail = $this->getAttributeByConfig('user_mail_attribute');
      if ($mail) {
        $account->setEmail($mail);
        if ($account->isNew()) {
          // externalauth sets 'init' to a non e-mail value so we will fix it.
          $account->set('init', $mail);
        }
      }
      else {
        $this->logger->critical("Error on synchronizing mail attribute: no email address available for Drupal user %id.", ['%id' => $account->id()]);
        drupal_set_message(t('Error synchronizing mail: no email address is provided by SAML.'), 'error');
      }
    }
  }

  // Helper function.
  public function getData() {
    return $this->auth->getAttributes();
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
      $attribute = $this->auth->getAttribute($attribute_name);
      if (!empty($attribute[0])) {
        return $attribute[0];
      }
    }
  }

  /**
   * @return bool if a valid user was fetched from the saml assertion this request.
   */
  protected function isAuthenticated() {
    return $this->auth->isAuthenticated();
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
        'x509cert' => $config->get('sp_x509_certificate'),
        'privateKey' => $config->get('sp_private_key'),
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
