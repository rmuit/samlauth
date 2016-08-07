<?php

/**
 * @file
 * Contains Drupal\samlauth\SamlService.
 */

namespace Drupal\samlauth;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Url;
use OneLogin_Saml2_Auth;
use OneLogin_Saml2_Error;
use InvalidArgumentException;

/**
 * Class SamlService.
 *
 * @package Drupal\samlauth
 */
class SamlService {

  /**
   * A configuration object containing samlauth settings.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * @var \OneLogin_Saml2_Auth
   */
  protected $auth;

  /**
   * Constructor for Drupal\samlauth\SamlService.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   */
  public function __construct(ConfigFactoryInterface $config_factory) {
    $this->config = $config_factory->get('samlauth.authentication');
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

  // Helper function.
  public function getData() {
    return $this->auth->getAttributes();
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
