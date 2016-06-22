<?php

/**
 * @file
 * Contains Drupal\samlauth\SamlService.
 */

namespace Drupal\samlauth;
use \Exception;
use Drupal\Core\Session\AccountInterface;
use Drupal\user\Entity\User;
use Drupal\user\UserDataInterface;

/**
 * Class SamlUserService.
 *
 * @package Drupal\samlauth
 */
class SamlUserService {

  /**
   * Instance of UserDataInterface.
   *
   * @var Drupal\user\UserDataInterface $user_data
   */
  protected $user_data;

  /**
   * Instance of ConfigFactoryInterface.
   *
   * @var Drupal\Core\Config\ConfigFactoryInterface $config
   */
  protected $config;

  /**
   * Constructor for SamlUserService.
   *
   * @param \Drupal\user\UserDataInterface $user_data
   */
  public function __construct(UserDataInterface $user_data) {
    $this->user_data = $user_data;
    // @TODO: How should this be injected?
    $this->config = \Drupal::config('samlauth.authentication');
  }

  /**
   * Find a user by a given SAML unique ID.
   *
   * @param string $id
   *   The unique ID to search for.
   * @return integer|null
   *   The uid of the matching user or NULL if we can't find one.
   */
  public function findUidByUniqueId($id) {
    if (empty($id)) {
      // We don't support an 'empty' unique ID value; we can't match it reliably
      // and also do not want to end up creating new users every time.
      throw new Exception('Unique ID is empty.');
    }
    $user_data = $this->user_data->get('samlauth', NULL, 'saml_id');
    if ($user_data) {
      // Non-strict matching because we don't want to assume that types from the
      // data storage and received SAML properties are the same.
      $user_data = array_keys($user_data, $id);
    }

    if (empty($user_data)) {
      $return = NULL;
    }
    elseif (!is_array($user_data)) {
      throw new Exception('Mapping the unique ID returned an unexpected result.');
    }
    elseif (count($user_data) === 1) {
      $return = key($user_data);
    }
    else {
      throw new Exception('There are duplicates of the unique ID.');
    }
    return $return;
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
    if (!isset($saml_data[$unique_id_attribute][0])) {
      throw new Exception('Configured unique ID is not present in SAML response!');
    }

    $unique_id = $saml_data[$unique_id_attribute][0];
    $uid = $this->findUidByUniqueId($unique_id);

    if (!$uid) {
      $mail_attribute = $this->config->get('map_users_email');
      if ($this->config->get('map_users') && !empty($saml_data[$mail_attribute]) && $account = user_load_by_mail($saml_data[$mail_attribute])) {
        $this->associateSamlIdWithAccount($unique_id, $account);
      }
      else if ($this->config->get('create_users')) {
        $account = $this->createUserFromSamlData($saml_data);
      }
      else {
        throw new Exception('No existing user account matches the SAML ID provided. This authentication service is not configured to create new accounts.');
      }
    }
    else {
      $account = User::load($uid);
      if (!$account) {
        throw new Exception('Could not load user by given unique ID.');
      }
    }

    if ($account->isBlocked()) {
      throw new Exception('Requested account is blocked.');
    }

    user_login_finalize($account);
  }

  /**
   * Ends the current session.
   */
  public function logout() {
    user_logout();
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
   * Create a new user from SAML response data.
   *
   * @param array $saml_data
   * @return static
   * @throws \Exception
   */
  protected function createUserFromSamlData(array $saml_data) {
    $user_unique_attribute = $this->config->get('unique_id_attribute');
    $user_name_attribute = $this->config->get('user_name_attribute');
    $user_mail_attribute = $this->config->get('user_mail_attribute');
    if (!isset($saml_data[$user_name_attribute][0])) {
      throw new Exception('Missing name attribute.');
    }
    if (!isset($saml_data[$user_mail_attribute][0])) {
      throw new Exception('Missing mail attribute.');
    }

    $account = User::create();
    $account->setUsername($saml_data[$user_name_attribute][0]);
    $account->setPassword(user_password(50));
    $account->setEmail($saml_data[$user_mail_attribute][0]);
    $account->activate();

    // Allow other users to change/set user properties before saving.
    \Drupal::moduleHandler()->alter('samlauth_new_user', $account, $saml_data);

    $account->save();

    // Save the unique ID for later use.
    $this->associateSamlIdWithAccount($saml_data[$user_unique_attribute][0], $account);

    return $account;
  }

  /**
   * Ensure that a SAML id is associated with a given user account.
   *
   * This function is idempotent.
   *
   * @param $saml_id
   * @param \Drupal\Core\Session\AccountInterface $account
   */
  protected function associateSamlIdWithAccount($saml_id, AccountInterface $account) {
    $this->user_data->set('samlauth', $account->id(), 'saml_id', $saml_id);
  }
}
