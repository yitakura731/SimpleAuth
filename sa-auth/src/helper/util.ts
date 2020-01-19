import * as dotenv from 'dotenv';
dotenv.config({ path: '/app.env' });

export default class Util {
  public static checkEmpty(target: string, message: string) {
    if (target == null || target === '') {
      throw new TypeError(message);
    }
  }

  public static checkNull(target: string, message: string) {
    if (target == null) {
      throw new TypeError(message);
    }
  }
}
