import { ConflictException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './user.model';
import { CreateUserDto } from './dto/user.dto';
import { hash } from 'bcrypt';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async create(dto: CreateUserDto) {
    const user = await this.userModel.findOne({ email: dto.email });

    if (user) {
      throw new ConflictException('User already exists');
    }

    const hashedPassword = await hash(dto.password, 10);

    const newUser = await this.userModel.create({
      ...dto,
      password: hashedPassword,
    });

    const { password, ...result } = newUser.toObject();
    return result;
  }

  async findByEmail(email: string) {
    return await this.userModel.findOne({ email });
  }

  async findByName(name: string): Promise<User> {
    return await this.userModel.findOne({ name: name }).exec();
  }
}
