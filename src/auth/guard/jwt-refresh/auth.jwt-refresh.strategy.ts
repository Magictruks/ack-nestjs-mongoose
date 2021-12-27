import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
    Strategy,
    'jwtRefresh'
) {
    constructor(private readonly configService: ConfigService) {
        super({
            // jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            jwtFromRequest:ExtractJwt.fromExtractors([(request:Request) => {
                const data = request?.cookies["refresh-cookie"];
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
                'auth.jwt.refreshToken.secretKey'
            )
        });
    }

    async validate(payload: Record<string, any>): Promise<Record<string, any>> {
        return payload;
    }
}
