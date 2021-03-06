<?php

namespace App\Controller;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    /**
     * @Route("/users", name="users")
     */
    public function users(): Response
    {
        $users = $this->getDoctrine()
            ->getRepository(User::class)
            ->createQueryBuilder('users')
            ->getQuery()
            ->getArrayResult();

        return $this->json($users);
    }
}
