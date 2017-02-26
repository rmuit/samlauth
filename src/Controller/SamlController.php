<?php

namespace Drupal\samlauth\Controller;

use Exception;
use Drupal\samlauth\SamlService;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\Core\Utility\Error;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Returns responses for samlauth module routes.
 */
class SamlController extends ControllerBase {

  /**
   * The samlauth SAML service.
   *
   * @var \Drupal\samlauth\SamlService
   */
  protected $saml;

  /**
   * Constructor for Drupal\samlauth\Controller\SamlController.
   *
   * @param \Drupal\samlauth\SamlService $saml
   *   The samlauth SAML service.
   */
  public function __construct(SamlService $saml) {
    $this->saml = $saml;
  }

  /**
   * Factory method for dependency injection container.
   *
   * @param \Symfony\Component\DependencyInjection\ContainerInterface $container
   * @return static
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('samlauth.saml')
    );
  }

  /**
   * Initiates a SAML2 authentication flow.
   *
   * This should redirect to the Login service on the IDP and then to our ACS.
   */
  public function login() {
    try {
      $this->saml->login();
      // We don't return here unless something is fundamentally wrong inside the
      // SAML Toolkit sources.
      throw new Exception('Not redirected to SAML IDP');
    }
    catch (Exception $e) {
      $this->handleException($e, 'initiating SAML login');
    }
    return new RedirectResponse(Url::fromRoute('<front>', [], ['absolute' => TRUE])->toString());
  }

  /**
   * Initiate a SAML2 logout flow.
   *
   * This should redirect to the SLS service on the IDP and then to our SLS.
   */
  public function logout() {
    try {
      $this->saml->logout();
      // We don't return here unless something is fundamentally wrong inside the
      // SAML Toolkit sources.
      throw new Exception('Not redirected to SAML IDP');
    }
    catch (Exception $e) {
      $this->handleException($e, 'initiating SAML logout');
    }
    return new RedirectResponse(Url::fromRoute('<front>', [], ['absolute' => TRUE])->toString());
  }

  /**
   * Displays service provider metadata XML for iDP autoconfiguration.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   */
  public function metadata() {
    try {
      $metadata = $this->saml->getMetadata();
    }
    catch (Exception $e) {
      $this->handleException($e, 'processing SAML SP metadata');
      return new RedirectResponse(Url::fromRoute('<front>', [], ['absolute' => TRUE])->toString());
    }

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
    try {
      $this->saml->acs();
      $route = $this->saml->getPostLoginDestination();
      $url = Url::fromRoute($route, [], ['absolute' => TRUE])->toString();
    }
    catch (Exception $e) {
      $this->handleException($e, 'processing SAML authentication response');
      $url = Url::fromRoute('<front>', [], ['absolute' => TRUE])->toString();
    }

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
   *   for authenticated user. So in a logout flow where the user starts at
   *   /saml/logout, this will never be executed and the user gets an "Access
   *   denied" message when returning to /saml/sls; this code is never executed.
   *   We should probably change the access rights and do more checking inside
   *   this function whether we should still log out.
   */
  public function sls() {
    try {
      $this->saml->sls();
      $route = $this->saml->getPostLogoutDestination();
      $url = Url::fromRoute($route, [], ['absolute' => TRUE])->toString();
    }
    catch (Exception $e) {
      $this->handleException($e, 'processing SAML aingle-logout response');
      $url = Url::fromRoute('<front>', [], ['absolute' => TRUE])->toString();
    }

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

  /**
   * Displays error message and logs full exception.
   *
   * @param $exception
   *   The exception thrown.
   * @param string $while
   *   A description of when the error was encountered.
   */
  protected function handleException($exception, $while = '') {
    if ($while) {
      $while = " $while";
    }
    // We use the same format for logging as Drupal's ExceptionLoggingSubscriber
    // except we also specify where the error was enocuntered. (The options are
    // limited, so we make this part of the message, not a context parameter.)
    $error = Error::decodeException($exception);
    unset($error['severity_level']);
    $this->getLogger('samlauth')->critical("%type encountered while $while: @message in %function (line %line of %file).", $error);
    // Don't expose the error to prevent information leakage; the user probably
    // can't do much with it anyway. But hint that more details are available.
    drupal_set_message("Error $while; details have been logged.", 'error');
  }
}
