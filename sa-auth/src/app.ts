import * as bodyParser from 'body-parser';
import * as boom from 'boom';
import * as cookieParser from 'cookie-parser';
import * as cors from 'cors';
import { config } from 'dotenv';
import * as express from 'express';
import * as i18Next from 'i18next';
import * as middleware from 'i18next-express-middleware';
import * as fsBackend from 'i18next-node-fs-backend';
import * as logger from 'morgan';
import * as passport from 'passport';
import { resolve } from 'path';
import * as swaggerJSDoc from 'swagger-jsdoc';
import * as swaggerUi from 'swagger-ui-express';
config({ path: resolve(__dirname, '../auth.env') });

import authController from './controller/authController';

const app = express();
const i18next: i18Next.i18n = (i18Next as any) as i18Next.i18n;

app.set('views', 'public');
app.set('view engine', 'ejs');
app.use(logger('dev'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static('public'));
app.use(passport.initialize());
app.use(passport.session());

app.options('*', cors());

/**
 * i18next
 */
i18next
  .use(middleware.LanguageDetector)
  .use(fsBackend)
  .init({
    backend: {
      loadPath: 'public/locales/{{lng}}/{{ns}}.json',
    },
    fallbackLng: 'ja',
    lng: 'ja',
  });
app.use(middleware.handle(i18next));

app.options('*', cors());

/**
 * Swagger
 */
const swaggerSpec = swaggerJSDoc({
  apis: ['**/*.ts'],
  swaggerDefinition: {
    basePath: `/${process.env.APP_NAME}/api`,
    consumes: ['application/json'],
    info: {
      description: 'Simple Authentication API',
      title: 'Simple Authentication API',
      version: '1.2.0',
    },
    produces: ['application/json'],
    swagger: '2.0',
  },
});
app.use(`/${process.env.APP_NAME}/api/docs`, swaggerUi.serve);
app.get(`/${process.env.APP_NAME}/api/docs`, swaggerUi.setup(swaggerSpec));

app.use(`/${process.env.APP_NAME}/api/auth`, authController);

app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  next(boom.notFound(i18next.t('errorNotFound')));
});

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  // tslint:disable-next-line: no-console
  console.log(err);
  if (boom.isBoom(err)) {
    res.status(err.output.statusCode).json(err.output.payload);
  } else if (err instanceof TypeError) {
    res.status(403).json({
      StatusCode: 403,
      error: 'Invalid Request Parameter',
      message: err.message,
    });
  } else {
    res.status(500).json({
      StatusCode: 500,
      error: 'Internal Server Error',
      message: err.message,
    });
  }
});

export { app };
