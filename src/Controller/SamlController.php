<?php

/**
 * @file
 * Contains Drupal\samlauth\Controller\SamlController.
 */

namespace Drupal\samlauth\Controller;

use Exception;
use Drupal\samlauth\SamlService;
use Drupal\samlauth\SamlUserService;
use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class SamlController.
 *
 * @package Drupal\samlauth\Controller
 */
class SamlController extends ControllerBase {

  /**
   * The samlauth SAML service.
   *
   * @var \Drupal\samlauth\SamlService
   */
  protected $saml;

  /**
   * @var \Drupal\samlauth\SamlUserService
   */
  protected $saml_user;

  /**
   * Constructor for Drupal\samlauth\Controller\SamlController.
   *
   * @param \Drupal\samlauth\SamlService $saml
   *   The samlauth SAML service.
   * @param \Drupal\samlauth\SamlUserService $saml_user
   */
  public function __construct(SamlService $saml, SamlUserService $saml_user) {
    $this->saml = $saml;
    $this->saml_user = $saml_user;
  }

  /**
   * Factory method for dependency injection container.
   *
   * @param \Symfony\Component\DependencyInjection\ContainerInterface $container
   * @return static
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('samlauth.saml'),
      $container->get('samlauth.saml_user')
    );
  }

  /**
   * Initiates a SAML2 authentication flow.
   *
   * This should redirect to the Login service on the IDP and then to our ACS.
   */
  public function login() {
    $this->saml->login();
  }

  /**
   * Initiate a SAML2 logout flow.
   *
   * This should redirect to the SLS service on the IDP and then to our SLS.
   */
  public function logout() {
    $this->saml->logout();
  }

  /**
   * Displays service provider metadata XML for iDP autoconfiguration.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   */
  public function metadata() {
    $metadata = $this->saml->getMetadata();
    $response = new Response($metadata, 200);
    $response->headers->set('Content-Type', 'text/xml');
    return $response;
  }

  /**
   * Attribute Consumer Service.
   *
   * This is usually the second step in the authentication flow; the Login
   * service on the IDP should redirect (or: execute a POST request to) here.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   */
  public function acs() {
    $errors = $this->saml->acs();
    if (!empty($errors)) {
      drupal_set_message($this->t('An error occured.'), 'error');
      return new RedirectResponse('/');
    }

    try {
      $saml_data = $this->saml->getData();
      $this->saml_user->handleSamlData($saml_data);
    }
    catch (Exception $e) {
      drupal_set_message($e->getMessage(), 'error');
    }

    $route = $this->saml_user->getPostLoginDestination();
    $url = \Drupal::urlGenerator()->generateFromRoute($route);
    return new RedirectResponse($url);
  }

  /**
   * Single Logout Service.
   *
   * This is usually the second step in the logout flow; the SLS service on the
   * IDP should redirect here.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *
   * @todo we already called user_logout() at the start of the logout
   *   procedure i.e. at logout(). The route that leads here is only accessible
   *   for authenticated user. So will this never be executed and should we
   *   change this code?
   */
  public function sls() {
    $this->saml->sls();

    $route = $this->saml_user->getPostLogoutDestination();
    $url = \Drupal::urlGenerator()->generateFromRoute($route);
    return new RedirectResponse($url);
  }

  /**
   * Change password redirector.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   */
  public function changepw() {
    $url = \Drupal::config('samlauth.authentication')->get('idp_change_password_service');
    return new RedirectResponse($url);
  }

}
