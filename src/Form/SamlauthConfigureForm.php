<?php

namespace Drupal\samlauth\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Path\PathValidatorInterface;
use Drupal\Core\Url;
use Drupal\Core\Utility\Token;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Provides a configuration form for samlauth module settings and IDP/SP info.
 */
class SamlauthConfigureForm extends ConfigFormBase {

  /**
   * The PathValidator service.
   *
   * @var \Drupal\Core\Path\PathValidatorInterface
   */
  protected $pathValidator;

  /**
   * The token service.
   *
   * @var \Drupal\Core\Utility\Token
   */
  protected $token;

  /**
   * Constructs a \Drupal\samlauth\Form\SamlauthConfigureForm object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The factory for configuration objects.
   * @param \Drupal\Core\Path\PathValidatorInterface $path_validator
   *   The PathValidator service.
   * @param \Drupal\Core\Utility\Token $token
   *   The token service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, PathValidatorInterface $path_validator, Token $token) {
    $this->setConfigFactory($config_factory);
    $this->pathValidator = $path_validator;
    $this->token = $token;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('path.validator'),
      $container->get('token')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'samlauth_configure_form';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'samlauth.authentication'
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('samlauth.authentication');

    $form['saml_login_logout'] = array(
      '#type' => 'fieldset',
      '#title' => $this->t('Login / Logout'),
    );

    // Show note for enabling "log in" or "log out" menu link item.
    if (Url::fromRoute('entity.menu.edit_form', ['menu' => 'account'])->access()) {
      $form['saml_login_logout']['menu_item'] = array(
        '#type' => 'markup',
        '#markup' => '<em>' . $this->t('Note: You <a href="@url">may want to enable</a> the "log in" / "log out" menu item and disable the original one.', array(
            '@url' => Url::fromRoute('entity.menu.edit_form', ['menu' => 'account'])
              ->toString()
          )) . '</em>',
      );
    }

    $form['saml_login_logout']['login_menu_item_title'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Login menu item title'),
      '#description' => $this->t('The title of the SAML login link. Defaults to "Log in".'),
      '#default_value' => $config->get('login_menu_item_title'),
    );

    $form['saml_login_logout']['logout_menu_item_title'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Logout menu item title'),
      '#description' => $this->t('The title of the SAML logout link. Defaults to "Log out".'),
      '#default_value' => $config->get('logout_menu_item_title'),
    );

    $form['saml_login_logout']['drupal_saml_login'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Allow SAML users to log in directly'),
      '#description' => $this->t('If this option is enabled, users that have a remote SAML ID will also be allowed to log in through the normal Drupal process (without the intervention of the configured identity provider). This option does not change anything to site layout (e.g. enabling menu links); you will need to do this yourself.'),
      '#default_value' => $config->get('drupal_saml_login'),
    );

    $form['saml_login_logout']['login_redirect_url'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Login redirect URL'),
      '#description' => $this->t("Define the default URL to redirect the user after login. Enter a internal path starting with a slash, or a absolute URL. Defaults to the logged-in user's account page."),
      '#default_value' => $config->get('login_redirect_url'),
    );

    $form['saml_login_logout']['logout_redirect_url'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Logout redirect URL'),
      '#description' => $this->t('Define the default URL to redirect the user after logout. Enter a internal path starting with a slash, or a absolute URL. Defaults to the front page.'),
      '#default_value' => $config->get('logout_redirect_url'),
    );

    $form['service_provider'] = array(
      '#type' => 'fieldset',
      '#title' => $this->t('Service Provider Configuration'),
    );

    $form['service_provider']['config_info'] = array(
      '#theme' => 'item_list',
      '#items' => array(
        $this->t('Metadata URL') . ': ' . \Drupal::urlGenerator()->generateFromRoute('samlauth.saml_controller_metadata', array(), array('absolute' => TRUE)),
        $this->t('Assertion Consumer Service') . ': ' . Url::fromRoute('samlauth.saml_controller_acs', array(), array('absolute' => TRUE))->toString(),
        $this->t('Single Logout Service') . ': ' . Url::fromRoute('samlauth.saml_controller_sls', array(), array('absolute' => TRUE))->toString(),
      ),
      '#empty' => array(),
      '#list_type' => 'ul',
    );

    $form['service_provider']['sp_entity_id'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Entity ID'),
      '#description' => $this->t('Specifies the identifier to be used to represent the SP.'),
      '#default_value' => $config->get('sp_entity_id'),
    );

    $form['service_provider']['sp_name_id_format'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Name ID Format'),
      '#description' => $this->t('Specify the NameIDFormat attribute to request from the identity provider'),
      '#default_value' => $config->get('sp_name_id_format'),
    );

    $cert_folder = $config->get('sp_cert_folder');
    $sp_x509_certificate = $config->get('sp_x509_certificate');
    $sp_private_key = $config->get('sp_private_key');

    $form['service_provider']['sp_cert_type'] = array(
      '#type' => 'select',
      '#title' => $this->t('Type of configuration to save for the certificates'),
      '#required' => TRUE,
      '#options' => [
        'folder' => $this->t('Folder name'),
        'fields' => $this->t('Cert/key value'),
      ],
      // Prefer folder over certs, like SamlService::reformatConfig(), but if
      // both are empty then default to folder here.
      '#default_value' => $cert_folder || (!$sp_x509_certificate && !$sp_private_key) ? 'folder' : 'fields',
    );

    $form['service_provider']['sp_x509_certificate'] = array(
      '#type' => 'textarea',
      '#title' => $this->t('x509 Certificate'),
      '#description' => $this->t('Public x509 certificate of the SP. No line breaks or BEGIN CERTIFICATE or END CERTIFICATE lines.'),
      '#default_value' => $config->get('sp_x509_certificate'),
      '#states' => array(
        'visible' => array(
          array(':input[name="sp_cert_type"]' => array('value' => 'fields')),
        ),
      ),
    );

    $form['service_provider']['sp_private_key'] = array(
      '#type' => 'textarea',
      '#title' => $this->t('Private Key'),
      '#description' => $this->t('Private key for SP. No line breaks or BEGIN CERTIFICATE or END CERTIFICATE lines.'),
      '#default_value' => $config->get('sp_private_key'),
      '#states' => array(
        'visible' => array(
          array(':input[name="sp_cert_type"]' => array('value' => 'fields')),
        ),
      ),
    );

    $form['service_provider']['sp_cert_folder'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Certificate folder'),
      '#description' => $this->t('Set the path to the folder containing a /certs subfolder and the /certs/sp.key (private key) and /certs/sp.crt (public cert) files. The names of the subfolder and files are mandated by the external SAML Toolkit library.'),
      '#default_value' => $cert_folder,
      '#states' => array(
        'visible' => array(
          array(':input[name="sp_cert_type"]' => array('value' => 'folder')),
        ),
      ),
    );

    $form['identity_provider'] = array(
      '#type' => 'fieldset',
      '#title' => $this->t('Identity Provider Configuration'),
    );

    // @TODO: Allow a user to automagically populate this by providing a metadata URL for the iDP.
//    $form['identity_provider']['idp_metadata_url'] = array(
//      '#type' => 'url',
//      '#title' => $this->t('Metadata URL'),
//      '#description' => $this->t('URL of the XML metadata for the identity provider'),
//      '#default_value' => $config->get('idp_metadata_url'),
//    );

    $form['identity_provider']['idp_entity_id'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Entity ID'),
      '#description' => $this->t('Specifies the identifier to be used to represent the IDP.'),
      '#default_value' => $config->get('idp_entity_id'),
    );

    $form['identity_provider']['idp_single_sign_on_service'] = array(
      '#type' => 'url',
      '#title' => $this->t('Single Sign On Service'),
      '#description' => $this->t('URL where the SP will send the authentication request message.'),
      '#default_value' => $config->get('idp_single_sign_on_service'),
    );

    $form['identity_provider']['idp_single_log_out_service'] = array(
      '#type' => 'url',
      '#title' => $this->t('Single Log Out Service'),
      '#description' => $this->t('URL where the SP will send the logout request message.'),
      '#default_value' => $config->get('idp_single_log_out_service'),
    );

    $form['identity_provider']['idp_change_password_service'] = array(
      '#type' => 'url',
      '#title' => $this->t('Change Password Service'),
      '#description' => $this->t('URL where users will be redirected to change their password.'),
      '#default_value' => $config->get('idp_change_password_service'),
    );

    $form['identity_provider']['idp_x509_certificate'] = array(
      '#type' => 'textarea',
      '#title' => $this->t('x509 Certificate'),
      '#description' => $this->t('Public x509 certificate of the IdP. The external SAML Toolkit library does not allow configuring this as a separate file.'),
      '#default_value' => $config->get('idp_x509_certificate'),
    );

    $form['user_info'] = array(
      '#title' => $this->t('User Info and Syncing'),
      '#type' => 'fieldset',
    );

    $form['user_info']['unique_id_attribute'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Unique identifier attribute'),
      '#description' => $this->t("Specify a SAML attribute that is always going to be unique per user. This will be used to identify local users through an 'auth mapping' (which is stored separately from the user account info).<br>Example: <em>eduPersonPrincipalName</em> or <em>eduPersonTargetedID</em>"),
      '#default_value' => $config->get('unique_id_attribute') ?: 'eduPersonTargetedID',
    );

    $form['user_info']['map_users'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Attempt to map SAML users to existing local users'),
      '#description' => $this->t('If this option is enabled and the SAML authentication response is not mapped to a user yet, but the name / e-mail attribute matches an existing non-mapped user, the SAML user will be mapped to the user.'),
      '#default_value' => $config->get('map_users'),
    );

    $form['user_info']['create_users'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Create users specified by SAML server'),
      '#description' => $this->t('If this option is enabled and the SAML authentication response is not mapped to a user, a new user is created using the name / e-mail attributes from the response.'),
      '#default_value' => $config->get('create_users'),
    );

    $form['user_info']['sync_name'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Synchronize user name on every login'),
      '#default_value' => $config->get('sync_name'),
      '#description' => $this->t('If this option is enabled, any changes to the name of SAML users will be propagated into Drupal user accounts.'),
    );

    $form['user_info']['sync_mail'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Synchronize email address on every login'),
      '#default_value' => $config->get('sync_mail'),
      '#description' => $this->t('If this option is enabled, any changes to the email address of SAML users will be propagated into Drupal user accounts.'),
    );

    $form['user_info']['user_name_attribute'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('User name attribute'),
      '#description' => $this->t('When SAML users are mapped / created, this field specifies which SAML attribute should be used for the Drupal user name.<br />Example: <em>cn</em> or <em>eduPersonPrincipalName</em>'),
      '#default_value' => $config->get('user_name_attribute') ?: 'cn',
      '#states' => array(
        'invisible' => array(
          ':input[name="map_users"]' => array('checked' => FALSE),
          ':input[name="create_users"]' => array('checked' => FALSE),
          ':input[name="sync_name"]' => array('checked' => FALSE),
        ),
      ),
    );

    $form['user_info']['user_mail_attribute'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('User email attribute'),
      '#description' => $this->t('When SAML users are mapped / created, this field specifies which SAML attribute should be used for the Drupal email address.<br />Example: <em>mail</em>'),
      '#default_value' => $config->get('user_mail_attribute') ?: 'email',
      '#states' => array(
        'invisible' => array(
          ':input[name="map_users"]' => array('checked' => FALSE),
          ':input[name="create_users"]' => array('checked' => FALSE),
          ':input[name="sync_mail"]' => array('checked' => FALSE),
        ),
      ),
    );

    $form['security'] = array(
      '#title' => $this->t('Security Options'),
      '#type' => 'fieldset',
    );

    $form['security']['strict'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Strict mode'),
      '#description' => $this->t('In strict mode, any validation failures or unsigned SAML messages which are requested to be signed (according to your settings) will cause the SAML conversation to be terminated. In production environments, this <em>must</em> be set.'),
      '#default_value' => $config->get('strict'),
    );

    $form['security']['security_authn_requests_sign'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Sign authentication requests'),
      '#description' => $this->t('Requests sent to the Single Sign-On Service of the IDP will include a signature.'),
      '#default_value' => $config->get('security_authn_requests_sign'),
    );

    $form['security']['security_messages_sign'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Request messages to be signed'),
      '#description' => $this->t('Response messages from the IDP are expected to be signed.'),
      '#default_value' => $config->get('security_messages_sign'),
      '#states' => array(
        'disabled' => array(
          ':input[name="strict"]' => array('checked' => FALSE),
        ),
      ),
    );

    $form['security']['security_request_authn_context'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t('Request authn context'),
      '#default_value' => $config->get('security_request_authn_context'),
    );

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    parent::validateForm($form, $form_state);
    // @TODO: Validate cert. Might be able to just openssl_x509_parse().

    // Validate login/logout redirect URLs.
    $login_url_path = $form_state->getValue('login_redirect_url');
    if ($login_url_path) {
      $login_url_path = $this->token->replace($login_url_path);
      $login_url = $this->pathValidator->getUrlIfValidWithoutAccessCheck($login_url_path);
      if (!$login_url) {
        $form_state->setErrorByName('login_redirect_url', $this->t('The Login Redirect URL is not a valid path.'));
      }
    }
    $logout_url_path = $form_state->getValue('logout_redirect_url');
    if ($logout_url_path) {
      $logout_url_path = $this->token->replace($logout_url_path);
      $logout_url = $this->pathValidator->getUrlIfValidWithoutAccessCheck($logout_url_path);
      if (!$logout_url) {
        $form_state->setErrorByName('logout_redirect_url', $this->t('The Logout Redirect URL is not a valid path.'));
      }
    }

    // Validate certs folder. Don't allow the user to save an empty folder; if
    // they want to save incomplete config data, they can switch to 'fields'.
    $sp_cert_type = $form_state->getValue('sp_cert_type');
    $sp_cert_folder = $this->fixFolderPath($form_state->getValue('sp_cert_folder'));
    if ($sp_cert_type == 'folder') {
      if (empty($sp_cert_folder)) {
        $form_state->setErrorByName('sp_cert_folder', $this->t('@name field is required.', array('@name' => $form['service_provider']['sp_cert_folder']['#title'])));
      }
      elseif (!file_exists($sp_cert_folder . '/certs/sp.key') || !file_exists($sp_cert_folder . '/certs/sp.crt')) {
        $form_state->setErrorByName('sp_cert_folder', $this->t('The Certificate folder does not contain the required certs/sp.key or certs/sp.crt files.'));
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    parent::submitForm($form, $form_state);

    // Only store variables related to the sp_cert_type value. (If the user
    // switched from fields to folder, the cert/key values always get cleared
    // so no unused security sensitive data gets saved in the database.)
    $sp_cert_type = $form_state->getValue('sp_cert_type');
    $sp_x509_certificate = '';
    $sp_private_key = '';
    $sp_cert_folder = '';
    if ($sp_cert_type == 'folder') {
      $sp_cert_folder = $this->fixFolderPath($form_state->getValue('sp_cert_folder'));
    }
    else {
      $sp_x509_certificate = $form_state->getValue('sp_x509_certificate');
      $sp_private_key = $form_state->getValue('sp_private_key');
    }

    $this->config('samlauth.authentication')
      ->set('login_menu_item_title', $form_state->getValue('login_menu_item_title'))
      ->set('logout_menu_item_title', $form_state->getValue('logout_menu_item_title'))
      ->set('drupal_saml_login', $form_state->getValue('drupal_saml_login'))
      ->set('login_redirect_url', $form_state->getValue('login_redirect_url'))
      ->set('logout_redirect_url', $form_state->getValue('logout_redirect_url'))
      ->set('sp_entity_id', $form_state->getValue('sp_entity_id'))
      ->set('sp_name_id_format', $form_state->getValue('sp_name_id_format'))
      ->set('sp_x509_certificate', $sp_x509_certificate)
      ->set('sp_private_key', $sp_private_key)
      ->set('sp_cert_folder', $sp_cert_folder)
      ->set('idp_entity_id', $form_state->getValue('idp_entity_id'))
      ->set('idp_single_sign_on_service', $form_state->getValue('idp_single_sign_on_service'))
      ->set('idp_single_log_out_service', $form_state->getValue('idp_single_log_out_service'))
      ->set('idp_change_password_service', $form_state->getValue('idp_change_password_service'))
      ->set('idp_x509_certificate', $form_state->getValue('idp_x509_certificate'))
      ->set('unique_id_attribute', $form_state->getValue('unique_id_attribute'))
      ->set('map_users', $form_state->getValue('map_users'))
      ->set('create_users', $form_state->getValue('create_users'))
      ->set('sync_name', $form_state->getValue('sync_name'))
      ->set('sync_mail', $form_state->getValue('sync_mail'))
      ->set('user_name_attribute', $form_state->getValue('user_name_attribute'))
      ->set('user_mail_attribute', $form_state->getValue('user_mail_attribute'))
      ->set('security_authn_requests_sign', $form_state->getValue('security_authn_requests_sign'))
      ->set('security_messages_sign', $form_state->getValue('security_messages_sign'))
      ->set('security_request_authn_context', $form_state->getValue('security_request_authn_context'))
      ->set('strict', $form_state->getValue('strict'))
      ->save();
  }

  /**
   * Remove trailing slash from a folder name, to unify config values.
   */
  private function fixFolderPath($path) {
    if ($path) {
      $path =  rtrim($path, '/');
    }
    return $path;
  }

}
