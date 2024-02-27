import { ConflictException, Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './user.model';
import { CreateUserDto } from './dto/user.dto';
import { hash } from 'bcryptjs';

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);

  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async create(dto: CreateUserDto) {
    this.logger.debug(`Creating a new user with email ${dto.email}`);

    const user = await this.userModel.findOne({ email: dto.email });

    if (user) {
      this.logger.warn(`User with email ${dto.email} already exists`);
      throw new ConflictException('User already exists');
    }

    const hashedPassword = await hash(dto.password, 10);

    const newUser = await this.userModel.create({
      ...dto,
      password: hashedPassword,
    });

    this.logger.log(`User ${newUser.email} created`);

    const { password, ...result } = newUser.toObject();
    return result;
  }

  async findByEmail(email: string) {
    this.logger.debug(`Finding user with email ${email}`);
    const user = await this.userModel.findOne({ email });
    if (!user) {
      this.logger.warn(`User with email ${email} not found`);
      return null;
    }
    return user;
  }

  async findByName(name: string): Promise<User> {
    this.logger.debug(`Finding user with name ${name}`);
    const user = await this.userModel.findOne({ name: name }).exec();
    if (!user) {
      this.logger.warn(`User with name ${name} not found`);
      return null;
    }
    return user;
  }
}
