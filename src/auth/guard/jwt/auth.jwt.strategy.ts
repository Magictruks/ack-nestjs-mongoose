import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
    constructor(private readonly configService: ConfigService) {
        super({
            // jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            jwtFromRequest:ExtractJwt.fromExtractors([(request:Request) => {
                const data = request?.cookies["access-cookie"];
                if(!data){
                    return null;
                }
                return data
            }]),
            ignoreExpiration: false,
            jsonWebTokenOptions: {
                ignoreNotBefore: false
            },
            secretOrKey: configService.get<string>(
                'auth.jwt.accessToken.secretKey'
            )
        });
    }

    async validate(payload: Record<string, any>): Promise<Record<string, any>> {
        return payload;
    }
}
