<?php

/**
 * @file
 * Contains Drupal\samlauth\SamlUserService.
 */

namespace Drupal\samlauth;

use \Exception;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\externalauth\ExternalAuth;
use Psr\Log\LoggerInterface;

/**
 * Class SamlUserService.
 *
 * @package Drupal\samlauth
 */
class SamlUserService {

  /**
   * The ExternalAuth service.
   *
   * @var \Drupal\externalauth\ExternalAuth
   */
  protected $external_auth;

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
   * Constructor for SamlUserService.
   *
   * @param \Drupal\externalauth\ExternalAuth $external_auth
   *   The ExternalAuth service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The EntityTypeManager service.
   * @param \Psr\Log\LoggerInterface $logger
   *   A logger instance.
   */
  public function __construct(ExternalAuth $external_auth, ConfigFactoryInterface $config_factory, EntityTypeManagerInterface $entity_type_manager, LoggerInterface $logger) {
    $this->external_auth = $external_auth;
    $this->config = $config_factory->get('samlauth.authentication');
    $this->entityTypeManager = $entity_type_manager;
    $this->logger = $logger;
  }

  /**
   * Take appropriate action on provided SAML data.
   *
   * @param array $saml_data
   * @throws \Exception
   */
  public function handleSamlData(array $saml_data) {
    $unique_id_attribute = $this->config->get('unique_id_attribute');

    // We depend on the unique ID being present, so make sure it's there.
    if (empty($saml_data[$unique_id_attribute][0])) {
      if (isset($saml_data[$unique_id_attribute][0])) {
        throw new Exception('Configured unique ID value in SAML response is empty.');
      }
      else {
        throw new Exception('Configured unique ID is not present in SAML response.');
      }
    }

    $unique_id = $saml_data[$unique_id_attribute][0];
    $account = $this->external_auth->load($unique_id, 'samlauth');

    if (!$account) {
      $this->logger->debug('No matching local users found for unique SAML ID @saml_id.', array('@saml_id' => $unique_id));

      $mail_attribute = $this->config->get('map_users_email');
      if ($this->config->get('map_users') && !empty($saml_data[$mail_attribute])
          && $account_search = $this->entityTypeManager->getStorage('user')->loadByProperties(array('mail' => $saml_data[$mail_attribute]))) {
        $account = reset($account_search);
        $this->logger->info('Matching local user @uid found for e-mail @mail in SAML data; associating user and logging in.', array('@mail' => $saml_data[$mail_attribute], '@uid' => $account->id()));
        // An existing 'samlauth' link for the account will be overwritten.
        $this->external_auth->linkExistingAccount($unique_id, 'samlauth', $account);
        $this->external_auth->userLoginFinalize($account, $unique_id, 'samlauth');
      }

      // @todo: we should first try to link existing accounts by _user_ too;
      //        externalauth will throw an exception if an account with the same
      //        name exists and we are doing nothing to prevent that.
      elseif ($this->config->get('create_users')) {
        $account = $this->external_auth->register($unique_id, 'samlauth');
        $this->external_auth->userLoginFinalize($account, $unique_id, 'samlauth');
      }
      else {
        throw new Exception('No existing user account matches the SAML ID provided. This authentication service is not configured to create new accounts.');
      }
    }
    elseif ($account->isBlocked()) {
      throw new Exception('Requested account is blocked.');
    }
    else {
      $this->external_auth->userLoginFinalize($account, $unique_id, 'samlauth');
    }
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

}
