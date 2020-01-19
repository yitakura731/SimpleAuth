import { connect } from 'http2';
import * as i18Next from 'i18next';
import * as jwt from 'jsonwebtoken';
import * as Passport from 'passport';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { Strategy as GitHubStrategy } from 'passport-github';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import * as passportJWT from 'passport-jwt';
import { Strategy as LocalStrategy } from 'passport-local';
import * as mysql from 'promise-mysql';
import util from '../helper/util';
import authUser from './authUser';

const i18next: i18Next.i18n = (i18Next as any) as i18Next.i18n;
const ExtractJWT = passportJWT.ExtractJwt;
const JWTStrategy = passportJWT.Strategy;
const dbport = process.env.DB_PORT || '3306';
const mysqlConfig = {
  database: process.env.DB_NAME,
  host: process.env.DB_HOST,
  port: parseInt(dbport, 10),
  password: process.env.DB_APP_USER_PASSWD,
  user: process.env.DB_APP_USER_NAME,
};

Passport.use(
  new LocalStrategy(
    {
      usernameField: 'loginId',
      passwordField: 'password',
    },
    (loginId: string, password: string, cb: any) => {
      mysql
        .createConnection(mysqlConfig)
        .then((conn) => {
          const result = conn.query('SELECT * FROM USER WHERE LOGINID = ?', [loginId]);
          conn.end();
          return result;
        })
        .then((result: any[]) => {
          if (result.length === 1) {
            const storedPassword: string = result[0].PASSWORD;
            if (storedPassword !== password) {
              return cb(null, false, { message: i18next.t('incorrectUser') });
            } else {
              const user: authUser = {
                userId: result[0].USERID,
                loginId: result[0].LOGINID,
                userNameJa: result[0].NAME_JA,
                userNameEn: result[0].NAME_EN,
                strategy: 'local2',
              };
              return cb(null, user);
            }
          } else {
            return cb(null, false, { message: i18next.t('incorrectUser') });
          }
        })
        .catch((err) => cb(err));
    },
  ),
);

Passport.use(
  new FacebookStrategy(
    {
      callbackURL: `${process.env.OAUTH_CALLBACK_URL}/api/auth/login/facebook/callback`,
      clientID: process.env.FACEBOOK_CLIENT_ID || 'dummy',
      clientSecret: process.env.FACEBOOK_CLIENT_SECREAT || 'dummy',
    },
    (accessToken: string, refreshToken: string, profile: Passport.Profile, cb: any) => {
      mysql
        .createConnection(mysqlConfig)
        .then((conn) => {
          const result = conn.query('SELECT * FROM USER WHERE FACEBOOK_UID = ?', [profile.id]);
          conn.end();
          return result;
        })
        .then((result: any[]) => {
          if (result.length > 0) {
            const user: authUser = {
              userId: result[0].USERID,
              loginId: result[0].LOGINID,
              userNameJa: result[0].NAME_JA,
              userNameEn: result[0].NAME_EN,
              strategy: 'facebook',
            };
            return cb(null, user);
          } else {
            return cb(null, false, { message: i18next.t('incorrectUser') });
          }
        })
        .catch((err) => cb(err));
    },
  ),
);

Passport.use(
  new GitHubStrategy(
    {
      callbackURL: `${process.env.OAUTH_CALLBACK_URL}/api/auth/login/github/callback`,
      clientID: process.env.GITHUB_CLIENT_ID || 'dummy',
      clientSecret: process.env.GITHUB_CLIENT_SECREAT || 'dummy',
    },
    (accessToken: string, refreshToken: string, profile: Passport.Profile, cb: any) => {
      mysql
        .createConnection(mysqlConfig)
        .then((conn) => {
          const result = conn.query('SELECT * FROM USER WHERE GITHUB_UID = ?', [profile.id]);
          conn.end();
          return result;
        })
        .then((result: any[]) => {
          if (result.length > 0) {
            const user: authUser = {
              userId: result[0].USERID,
              loginId: result[0].LOGINID,
              userNameJa: result[0].NAME_JA,
              userNameEn: result[0].NAME_EN,
              strategy: 'github',
            };
            return cb(null, user);
          } else {
            return cb(null, false, { message: i18next.t('incorrectUser') });
          }
        })
        .catch((err) => cb(err));
    },
  ),
);

Passport.use(
  new JWTStrategy(
    {
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'simple_repository',
    },
    (jwtPayload: any, cb: any) => {
      mysql
        .createConnection(mysqlConfig)
        .then((conn) => {
          const result = conn.query('SELECT * FROM USER WHERE USERID = ?', [jwtPayload.userId]);
          conn.end();
          return result;
        })
        .then((result: any[]) => {
          if (result.length === 1) {
            const user: authUser = {
              userId: result[0].USERID,
              loginId: result[0].LOGINID,
              userNameJa: result[0].NAME_JA,
              userNameEn: result[0].NAME_EN,
              strategy: jwtPayload.strategy,
            };
            return cb(null, user);
          } else {
            return cb(null, false, { message: i18next.t('incorrectUser') });
          }
        })
        .catch((err) => cb(err));
    },
  ),
);

export default class Authenticate {
  public createToken(user: any, strategy: string) {
    return jwt.sign(
      {
        userId: user.userId,
        strategy,
      },
      'simple_repository',
      { expiresIn: '300m' },
    );
  }

  public getUser(user: any) {
    return {
      userId: user.userId,
      loginId: user.loginId,
      name: {
        ja: user.userNameJa,
        en: user.userNameEn,
      },
      strategy: user.strategy,
    };
  }
}
