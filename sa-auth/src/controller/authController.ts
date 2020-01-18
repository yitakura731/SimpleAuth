import * as cors from 'cors';
import * as Express from 'express';
import * as passport from 'passport';

import Authenticate from '../model/authenticate';
const auth = new Authenticate();

const authController = Express.Router();

/**
 * @swagger
 * securityDefinitions:
 *   BearerAuth:
 *     type: apiKey
 *     name: Authorization
 *     in: header
 */

/**
 * @swagger
 * /auth/login/local:
 *   post:
 *     summary: Login as loca user account
 *     description: Login as loca user account
 *     parameters:
 *        - name: "user"
 *          in: "body"
 *          description: "ユーザー情報"
 *          required: true
 *          schema:
 *            type: object
 *            properties:
 *              userId:
 *                type: "string"
 *                example: admin
 *              password:
 *                type: "string"
 *                example: "admin"
 *     tags:
 *        - auth
 *     responses:
 *       200:
 *         description: Authenticate successfully
 */
authController.post('/login/local', cors(), (req: Express.Request, res: Express.Response, next: Express.NextFunction) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res.status(400).json({ info });
    }
    const token = auth.createToken(user, 'local');
    return res.status(200).json({ accessToken: `Bearer ${token}` });
  })(req, res, next);
});

authController.post(
  '/login/facebook',
  cors(),
  passport.authenticate('facebook', { session: false }),
  (req: Express.Request, res: Express.Response, next: Express.NextFunction) => {},
);

authController.get(
  '/login/facebook/callback',
  cors(),
  passport.authenticate('facebook', { session: false }),
  (req: Express.Request, res: Express.Response, next: Express.NextFunction) => {
    const token = auth.createToken(req.user, 'facebook');
    res.cookie('sr.auth.token', `Bearer ${token}`);
    return res.redirect(301, `/${process.env.APP_NAME}/home`);
  },
);

authController.post(
  '/login/github',
  cors(),
  passport.authenticate('github', { session: false }),
  (req: Express.Request, res: Express.Response, next: Express.NextFunction) => {},
);

authController.get(
  '/login/github/callback',
  cors(),
  passport.authenticate('github', { session: false }),
  (req: Express.Request, res: Express.Response, next: Express.NextFunction) => {
    const token = auth.createToken(req.user, 'github');
    res.cookie('sr.auth.token', `Bearer ${token}`);
    return res.redirect(301, `/${process.env.APP_NAME}/home`);
  },
);

/**
 * @swagger
 * /auth/me:
 *   get:
 *     summary: Get current login user information
 *     description: Get current login user information
 *     tags:
 *        - auth
 *     security:
 *        - BearerAuth: []
 *     responses:
 *       200:
 *         description: Authenticate successfully
 */
authController.get(
  '/me',
  cors(),
  passport.authenticate('jwt', { session: false }),
  (req: Express.Request, res: Express.Response, next: Express.NextFunction) => {
    const user = auth.getUser(req.user);
    return res.status(200).json(user);
  },
);

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     summary: Logout user information
 *     description: Logiout user information
 *     tags:
 *        - auth
 *     security:
 *        - BearerAuth: []
 *     responses:
 *       200:
 *         description: Authenticate successfully
 */
authController.post(
  '/logout',
  cors(),
  passport.authenticate('jwt', { session: false }),
  (req: Express.Request, res: Express.Response, next: Express.NextFunction) => {
    res.clearCookie('sr.auth.token');
    return res.status(200).json({});
  },
);

export default authController;
