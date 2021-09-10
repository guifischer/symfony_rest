<?php

namespace App\Controller;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class AuthController extends AbstractController
{
    /**
     * @Route("/login", name="app_login")
     */
    public function login(Request $request, UserPasswordEncoderInterface $passwordEncoder): Response
    {
        $content = json_decode($request->getContent());

        $email = $content->email ?? '';
        $password = $content->password ?? '';

        $user = $this->getDoctrine()
                ->getRepository(User::class)
                ->findOneBy(array('email' => $email));

        if (null === $user || !$passwordEncoder->isPasswordValid($user, $password)) {
            return $this->wrongCredentials();
        }

        $this->createAccessToken($user);

        return $this->json([
            "token" => $user->getToken(),
            "refresh_token" => $user->getRefreshToken(),
        ]);
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
        $user = $this->getUser();
        $user->eraseCredentials();
        
        $entityManager = $this->getDoctrine()->getManager();
        $entityManager->persist($user);
        $entityManager->flush();

        return $this->json($user->getToken());
    }

    /**
     * @Route("/refresh", name="app_refresh")
     */
    public function refresh(Request $request)
    {
        $content = json_decode($request->getContent());
        $refresh_token = $content->refresh_token ?? null;
        $token = $content->token ?? null;

        $user = $this->getDoctrine()
                ->getRepository(User::class)
                ->findOneBy(array('token' => $token));

        if (($refresh_token == null && $token == null) || $user == null || $user->getRefreshToken() != $refresh_token) {
            return $this->wrongCredentials();
        }
        
        $this->createAccessToken($user);

        return $this->json([
                    "token" => $user->getToken(),
                    "refresh_token" => $user->getRefreshToken(),
                ]);
    }

    protected function createAccessToken(User $user)
    {
        $entityManager = $this->getDoctrine()->getManager();
        
        $token = bin2hex(random_bytes(60));
        $expiresAt = new \DateTime('+1 day');
        $refresh_token = bin2hex(random_bytes(60));
        
        $user->setToken($token);
        $user->setExpiresAt($expiresAt);
        $user->setRefreshToken($refresh_token);
        $entityManager->persist($user);
        $entityManager->flush();
    }

    public function wrongCredentials()
    {
        $data = [
            'message' => 'Wrong credentials'
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }
}
