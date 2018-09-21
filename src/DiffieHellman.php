<?php
/**
 * Created by PhpStorm.
 * User: zogxray
 * Date: 20.09.18
 * Time: 13:06
 */

namespace Micseres\MicroServiceDH;

use Micseres\MicroServiceDH\Exception\DiffieHellmanException;

/**
 * Class DaffieHellman
 * @package Micseres\MicroServiceDH
 */
final class DiffieHellman
{
    /** @var resource */
    private $privateKey;

    /** @var resource */
    private $privateKeyDetails;
    /**
     * @var bool
     */
    private $isMaster;
    /**
     * @var int
     */
    private $primaryLength;
    /**
     * @var int
     */
    private $generatorLength;

    /**
     * DiffieHellman constructor.
     * @param bool $isMaster
     * @param int $primaryLength
     * @param int $generatorLength
     */
    public function __construct(bool $isMaster = false, int $primaryLength = 512, int $generatorLength = 2)
    {
        $this->isMaster = $isMaster;
        $this->primaryLength = $primaryLength;
        $this->generatorLength = $generatorLength;

        if (true === $isMaster) {
            $this->generatePrimaryAsMaster();
        }
    }

    private function generatePrimaryAsMaster(): void
    {
        do {
            $p = openssl_random_pseudo_bytes($this->primaryLength);

            $args = [];
            $args['p'] = $p;
            $args['g'] = openssl_random_pseudo_bytes($this->generatorLength);
            $this->privateKey = openssl_pkey_new(['dh' => $args]);
        } while (false === $this->privateKey);

        $this->privateKeyDetails = openssl_pkey_get_details($this->privateKey);
    }

    /**
     * @param string $primary
     * @param string $generator
     */
    public function generatePrimaryAsSlave(string $primary, string $generator): void
    {
        $args = [];
        $args['p'] = hex2bin($primary);
        $args['g'] = hex2bin($generator);
        $this->privateKey = openssl_pkey_new(['dh' => $args]);
        $this->privateKeyDetails = openssl_pkey_get_details($this->privateKey);
    }

    /**
     * @return string
     * @throws DiffieHellmanException
     */
    public function getPrime(): string
    {
        if (false === $this->privateKey) {
            throw new DiffieHellmanException('Generate primary key first');
        }

        return bin2hex($this->privateKeyDetails['dh']['p']);
    }

    /**
     * @return string
     * @throws DiffieHellmanException
     */
    public function getGenerator(): string
    {
        if (false === $this->privateKey) {
            throw new DiffieHellmanException('Generate primary key first');
        }

        return bin2hex($this->privateKeyDetails['dh']['g']);
    }

    /**
     * @return string
     * @throws DiffieHellmanException
     */
    public function getPublicKey(): string
    {
        if (false === $this->privateKey) {
            throw new DiffieHellmanException('Generate primary key first');
        }

        return bin2hex($this->privateKeyDetails['dh']['pub_key']);
    }

    /**
     * @param string $serverPublicKey
     * @return string
     * @throws DiffieHellmanException
     */
    public function getSharedKey(string $serverPublicKey): string
    {
        $sharedKey = openssl_dh_compute_key(hex2bin($serverPublicKey), $this->privateKey);

        if (false === $sharedKey) {
            throw new DiffieHellmanException('Cant generate shared key');
        }

        return bin2hex($sharedKey);
    }
}