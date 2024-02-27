import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { LoginDto } from './dto/auth.dto';
import { UserService } from 'src/user/user.service';
import { compare } from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async login(dto: LoginDto) {
    const user = await this.validateUser(dto);

    const payload = {
      username: user.email,
      sub: {
        name: user.name,
      },
    };

    const userData = {
      user: {
        email: user.email,
        name: user.name,
      },
      backend_tokens: {
        sign_token: await this.jwtService.signAsync(payload, {
          expiresIn: '20s',
          secret: process.env.JWT_SECRET,
        }),
        renew_token: await this.jwtService.signAsync(payload, {
          expiresIn: '1d',
          secret: process.env.JWT_REFRESH,
        }),
      },
    };
    this.logger.log(`userData: ${JSON.stringify(userData)}`);
    return userData;
  }

  async validateUser(dto: LoginDto) {
    const user = await this.userService.findByEmail(dto.email);

    if (user && (await compare(dto.password, user.password))) {
      const { password, ...result } = user.toObject();
      this.logger.log(`User ${dto.email} validated`);
      return result;
    }

    this.logger.warn(`Invalid credentials for user ${dto.email}`);
    throw new UnauthorizedException('Invalid credentials');
  }

  async refreshToken(user: any) {
    const payload = {
      username: user.username,
      sub: user.sub,
    };

    const tokens = {
      backend_tokens: {
        sign_token: await this.jwtService.signAsync(payload, {
          expiresIn: '20s',
          secret: process.env.JWT_SECRET,
        }),
        renew_token: await this.jwtService.signAsync(payload, {
          expiresIn: '1d',
          secret: process.env.JWT_REFRESH,
        }),
      },
    };
    this.logger.log(tokens);
    return tokens;
  }
}
