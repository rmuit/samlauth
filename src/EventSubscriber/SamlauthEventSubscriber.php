<?php

/**
 * @file
 * Contains \Drupal\samlauth\EventSubscriber\SamlauthEventSubscriber.
 */

namespace Drupal\samlauth\EventSubscriber;

use Drupal\samlauth\SamlService;
use Drupal\externalauth\Event\ExternalAuthEvents;
use Drupal\externalauth\Event\ExternalAuthAuthmapAlterEvent;
use Drupal\externalauth\Event\ExternalAuthRegisterEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * EXAMPLE CODE:
 *
 * Event subscriber for the samlauth module with minimal dependencies.
 *
 * @todo when this module or externalauth comes out of alpha and this code is
 *       still not used, it can be removed. (We can also start using the below
 *       externalAuthRegister() rather than the hook_user_presave; it depends
 *       on preference. We will just have to do two user_save()s for new users.
 */
class SamlauthEventSubscriber implements EventSubscriberInterface {

  /**
   * A configuration object.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $saml;

  /**
   * {@inheritdoc}
   *
   * @param \Drupal\samlauth\SamlService $saml
   *   The samlauth SAML service.
   */
  public function __construct(SamlService $saml) {
    $this->saml = $saml;
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[ExternalAuthEvents::AUTHMAP_ALTER][] = array('externalAuthAuthmapAlter');
    return $events;
  }

  /**
   * React on an ExternalAuth authmap_alter event.
   *
   * This is valid code but it can only set the username, not the e-mail, before
   * saving.
   *
   * @param ExternalAuthAuthmapAlterEvent $event
   *   The subscribed event.
   */
  public function externalAuthAuthmapAlter(ExternalAuthAuthmapAlterEvent $event) {
    // The event is called when creating/registering a new user and when linking
    // an existing account. (Only) in the first case, the username that we set
    // here will be used.
    if ($event->getProvider() === 'samlauth') {
      $user_name_at_idp = $this->saml->getAttributeByConfig('user_name_attribute');
      if ($user_name_at_idp) {
        $event->setUsername($user_name_at_idp);
      }
    }
  }


  /**
   * React on an ExternalAuth register event.
   *
   * This is valid code (actually, ripped from simplesamlphp module) but we do
   * the same on hook_user_insert() so we don't save the account twice.
   *
   * @param ExternalAuthRegisterEvent $event
   *   The subscribed event.
   */
//  public function externalAuthRegister(ExternalAuthRegisterEvent $event) {
//    if ($event->getProvider() === 'samlauth') {
//
//      $account = $event->getAccount();
//      $this->saml->synchronizeUserAttributes($account);
//
//      // Invoke a hook to let other modules alter the user account based on
//      // SAML attributes.
//      $account_altered = FALSE;
//      $attributes = $this->simplesaml->getAttributes();
//      foreach (\Drupal::moduleHandler()->getImplementations('simplesamlphp_auth_user_attributes') as $module) {
//        $return_value = \Drupal::moduleHandler()->invoke($module, 'simplesamlphp_auth_user_attributes', [$account, $attributes]);
//        if ($return_value instanceof UserInterface) {
//          if ($this->config->get('debug')) {
//            $this->logger->debug('Drupal user attributes have altered based on SAML attributes by %module module.', array(
//              '%module' => $module,
//            ));
//          }
//          $account_altered = TRUE;
//          $account = $return_value;
//        }
//      }
//
//      if ($account_altered) {
//        $account->save();
//      }
//    }
//  }


}
