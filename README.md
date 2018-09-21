# Micro Service Diffie Hellman Encryption

## Usage

Alice 
```php
$this->dh = new DiffieHellman(true);

$requestToBob = [
    'p' => $this->dh->getPrime(),
    'g', $this->dh->getGenerator(),
    'public_key', $this->dh->getPublicKey()
];

//...

$pass = $this->dh->getSharedKey($responseFromBob->public_key)
```

Bob

```php
$this->dh = new DiffieHellman(false);
$this->dh->generatePrimaryAsSlave($requestFromBob['p'], $requestFromBob['g']);
$pass = $this->dh->getSharedKey($requestFromBob->public_key)
```

## License

The Soft Deletable Bundle is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
