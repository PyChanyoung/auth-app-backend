import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class RefreshJwtGuard implements CanActivate {
  private readonly logger = new Logger(RefreshJwtGuard.name);

  constructor(private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      this.logger.warn('No refresh token provided');
      throw new UnauthorizedException();
    }
    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: process.env.JWT_REFRESH,
      });
      // this.logger.log(`Payload: ${JSON.stringify(payload)}`);

      // request['user'] = payload;
      request.user = { username: payload.username, sub: payload.sub };
      this.logger.log(`User ${request.user.sub.name} authenticated`);
    } catch (e) {
      this.logger.error(`Refresh token validation failed: ${e.stack}`);
      throw new UnauthorizedException();
    }

    return true;
  }

  private extractTokenFromHeader(request: Request) {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    if (type !== 'Refresh') {
      this.logger.warn(`Invalid token type: ${type}`);
      return undefined;
    }
    return token;
  }
}
