<?php

namespace App\Controller;

use App\Entity\AccessToken;
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

        return $this->json($user->getAccessToken()->getToken());
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
        $user = $this->getUser();
        
        $entityManager = $this->getDoctrine()->getEntityManager();
        $entityManager->remove($user->getAccessToken());
        $entityManager->flush();
    }

    protected function createAccessToken(User $user)
    {
        $entityManager = $this->getDoctrine()->getManager();

        if ($user->getAccessToken() != null) {
            $entityManager->remove($user->getAccessToken());
            $entityManager->flush();
        }
        
        $access_token = new AccessToken($user);
        $user->setAccessToken($access_token);

        $entityManager->persist($access_token);
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
