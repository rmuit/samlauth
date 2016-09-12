<?php

namespace Drupal\Tests\samlauth\Unit;

use Drupal\Tests\UnitTestCase;
use Drupal\samlauth\SamlAuthAccount;
use Symfony\Component\Yaml\Yaml;

/**
 * Class \Drupal\samlauth\Tests\SamlAuthAccountTest.
 */
class SamlAuthAccountTest extends UnitTestCase {

  protected $token;
  protected $config;
  protected $accountProxy;
  protected $externalAuth;
  protected $externalAuthMap;
  protected $entityTypeManager;

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    parent::setUp();

    // Create a mock \Drupal\Core\Config\ConfigFactoryInterface.
    $this->config = $this
      ->getConfigFactoryStub(
        [
          'samlauth.user.mapping' => $this->getUserMappingConfigContent(),
          'samlauth.user.settings' => $this->getUserSettingsConfigContent(),
        ]
      );

    // Create a mock \Drupal\Core\Utility\Token.
    $this->token = $this
      ->getMockBuilder('\Drupal\Core\Utility\Token')
      ->disableOriginalConstructor()
      ->getMock();

    // Create a mock \Drupal\Core\Session\AccountProxyInterface.
    $this->accountProxy = $this
      ->getMockBuilder('\Drupal\Core\Session\AccountProxyInterface')
      ->disableOriginalConstructor()
      ->getMock();

    // Create a mock \Drupal\externalauth\ExternalAuthInterface.
    $this->externalAuth = $this
      ->getMockBuilder('\Drupal\externalauth\ExternalAuthInterface')
      ->disableOriginalConstructor()
      ->getMock();

    // Create a mock \Drupal\externalauth\AuthmapInterface.
    $this->externalAuthMap = $this
      ->getMockBuilder('\Drupal\externalauth\AuthmapInterface')
      ->disableOriginalConstructor()
      ->getMock();

    // Create a mock \Drupal\Core\Entity\EntityTypeManagerInterface.
    $this->entityTypeManager = $this
      ->getMockBuilder('\Drupal\Core\Entity\EntityTypeManagerInterface')
      ->disableOriginalConstructor()
      ->getMock();
  }

  /**
   * Test id() method.
   */
  public function testId() {
    $this->accountProxy
      ->expects($this->once())
      ->method('id')
      ->willReturn(1);

    $this->assertEquals(1, $this->getInstance()->id());
  }

  /**
   * Test authname() method.
   */
  public function testAuthname() {
    $this->externalAuthMap
      ->expects($this->once())
      ->method('get')
      ->willReturn('test@example.com');

    $this->assertEquals('test@example.com', $this->getInstance()->authname());
  }

  /**
   * Test getAuthData() method.
   */
  public function testGetAuthData() {
    $records = [
      'data' => 'a:5:{s:8:"memberOf";a:1:{i:0;s:0:"";}s:14:"User.FirstName";a:1:{i:0;s:3:"Sam";}s:17:"PersonImmutableID";a:1:{i:0;s:0:"";}s:13:"User.LastName";a:1:{i:0;s:5:"Smith";}s:10:"User.email";a:1:{i:0;s:15:"sam@example.com";}}',
    ];

    $this->externalAuthMap
      ->expects($this->once())
      ->method('getAuthData')
      ->willReturn($records);

    $this->assertArrayEquals(unserialize($records['data']), $this->getInstance()->getAuthData());
  }

  /**
   * Test getUsername() method.
   */
  public function testGetUsername() {
    $account = $this
      ->getMockBuilder('\Drupal\Core\Session\AccountInterface')
      ->getMock();
    $account
      ->expects($this->once())
      ->method('isAuthenticated')
      ->willReturn(TRUE);

    $this->accountProxy
      ->expects($this->once())
      ->method('getAccount')
      ->willReturn($account);

    $user = $this
      ->getMockBuilder('\Drupal\user\UserInterface')
      ->disableOriginalConstructor()
      ->getMock();

    $storage = $this
      ->getMockBuilder('\Drupal\user\UserStorageInterface')
      ->disableOriginalConstructor()
      ->getMock();

    $storage->expects($this->once())
      ->method('load')
      ->willReturn($user);

    $this->entityTypeManager
      ->expects($this->once())
      ->method('getStorage')
      ->willReturn($storage);

    $this->token
      ->expects($this->once())
      ->method('replace')
      ->willReturn('Tester');

    $this->assertEquals('Tester', $this->getInstance()->getUsername());
  }

  /**
   * Test isExternal() method.
   */
  public function testIsExternal() {
    $this->externalAuthMap
      ->expects($this->once())
      ->method('get')
      ->willReturn(TRUE);

    $this->assertTrue($this->getInstance()->isExternal());
  }

  /**
   * Test isAuthenticated() method.
   */
  public function testIsAuthenticated() {
    $account = $this
      ->getMockBuilder('\Drupal\Core\Session\AccountInterface')
      ->getMock();
    $account
      ->expects($this->once())
      ->method('isAuthenticated')
      ->willReturn(TRUE);

    $this->accountProxy
      ->expects($this->once())
      ->method('getAccount')
      ->willReturn($account);

    $this->assertTrue($this->getInstance()->isAuthenticated());
  }

  /**
   * Get service instance.
   *
   * @return \Drupal\samlauth\SamlAuthAccount
   *   An SAML authenticated account object.
   */
  protected function getInstance() {
    return new SamlAuthAccount(
      $this->accountProxy,
      $this->externalAuth,
      $this->externalAuthMap,
      $this->config,
      $this->token,
      $this->entityTypeManager
    );
  }

  /**
   * Load fixtures file contents.
   *
   * @param \SplFileInfo $file_info
   *   A file info object.
   * @param bool $parse_yml
   *   Add a flag to determine if we should parse yml.
   *
   * @return mixed
   */
  protected function loadFixturesFileContents(\SplFileInfo $file_info, $parse_yml = TRUE) {
    $contents = file_get_contents($file_info);

    if (FALSE === $contents) {
      return NULL;
    }

    if ($file_info->getExtension() === 'yml' && $parse_yml) {
      return Yaml::parse($contents);
    }

    return $contents;
  }

  /**
   * Get fixtures the base path.
   *
   * @return string
   *   A path to the fixtures directory.
   */
  protected function getFixturesBasePath() {
    return __DIR__ . '/../../fixtures';
  }

  /**
   * Get user mapping configuration content.
   */
  protected function getUserMappingConfigContent() {
    $file = new \SplFileInfo(
      $this->getFixturesBasePath() . '/config/samlauth.user.mapping.yml'
    );

    return $this->loadFixturesFileContents($file);
  }

  /**
   * Get user settings configuration content.
   */
  protected function getUserSettingsConfigContent() {
    $file = new \SplFileInfo(
      $this->getFixturesBasePath() . '/config/samlauth.user.settings.yml'
    );

    return $this->loadFixturesFileContents($file);
  }
}
