<?php

namespace App\Controller;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Validator\Constraints\Collection;
use Symfony\Component\Validator\Constraints\Email;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class RegistrationController extends AbstractController
{
    private $validator;

    public function __construct(ValidatorInterface $validator)
    {
        $this->validator = $validator;
    }

    /**
     * @Route("/register", name="app_register")
     */
    public function register(Request $request, UserPasswordEncoderInterface $passwordEncoder): Response
    {
        $content = json_decode($request->getContent(), true);
        $errors = $this->validateForm($content);
        
        if (count($errors)) {
            return $this->json($errors, 400);
        }

        $user = new User();
        $user->setEmail($content["email"]);
        $user->setPassword(
            $passwordEncoder->encodePassword(
                $user,
                $content["password"]
            )
        );
        $user->setRoles(["ROLE_USER"]);

        $entityManager = $this->getDoctrine()->getManager();
        $entityManager->persist($user);
        $entityManager->flush();

        return $this->json(true);
    }

    public function validateForm($content)
    {
        $messages = [];

        $constraints = new Collection([
            'email' => [
                new NotBlank([
                    'message' => 'Please enter a email',
                ]),
                new Email([
                    'message' => 'The email {{ value }} is not a valid email.',
                ])
            ],
            'password' => [
                new NotBlank([
                    'message' => 'Please enter a password',
                ]),
                new Length([
                    'min' => 6,
                    'minMessage' => 'Your password should be at least {{ limit }} characters',
                    'max' => 4096,
                ]),
            ],
        ]);

        $errors = $this->validator->validate($content, $constraints);

        if (count($errors) > 0) {
            foreach ($errors as $error) {
                $messages[] = $error->getMessage();
            }
        }

        $user = $this->getDoctrine()
            ->getRepository(User::class)
            ->findOneByEmail($content["email"]);

        if ($user != null) {
            $messages[] = "Email already registered";
        }

        return $messages;
    }
}
