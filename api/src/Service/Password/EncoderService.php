<?php

namespace App\Service\Password;

use App\Exception\Password\PasswordException;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class EncoderService
{
    private const MINIMUM_LENGTH = 6;
    private UserPasswordEncoderInterface $encoder;
    public function __construct(UserPasswordEncoderInterface $userPasswordEncoder)
    {
        $this->encoder = $userPasswordEncoder;
    }

    /**
     * @return UserPasswordEncoderInterface
     */
    public function generateEncodedPassword(UserInterface $user, string $password): string
    {
        if (self::MINIMUM_LENGTH > \strlen($password)) {
            throw PasswordException::invalidLenght();
        }
        return $this->encoder->encodePassword($user, $password);
    }

    public function isValidPassword(User $user, string $oldPassword): bool
    {
        return $this->encoder->isPasswordValid($user, $oldPassword);
    }
}