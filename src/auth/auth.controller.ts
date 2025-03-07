import {
    Controller,
    Post,
    Body,
    HttpStatus,
    HttpCode,
    NotFoundException,
    BadRequestException,
    UnauthorizedException,
    ForbiddenException, Res, Req, Get
} from '@nestjs/common';
import { AuthService } from 'src/auth/auth.service';
import { UserService } from 'src/user/user.service';
import { IUserDocument } from 'src/user/user.interface';
import { Logger as DebuggerService } from 'winston';
import { Debugger } from 'src/debugger/debugger.decorator';
import { classToPlain } from 'class-transformer';
import { RequestValidationPipe } from 'src/request/pipe/request.validation.pipe';
import { AuthLoginValidation } from './validation/auth.login.validation';
import { LoggerService } from 'src/logger/logger.service';
import { ENUM_LOGGER_ACTION } from 'src/logger/logger.constant';
import { AuthJwtGuard, AuthJwtRefreshGuard, User } from './auth.decorator';
import { Response } from 'src/response/response.decorator';
import { IResponse } from 'src/response/response.interface';
import { UserLoginTransformer } from 'src/user/transformer/user.login.transformer';
import {
    ENUM_AUTH_STATUS_CODE_ERROR,
    ENUM_AUTH_STATUS_CODE_SUCCESS
} from './auth.constant';
import { ENUM_USER_STATUS_CODE_ERROR } from 'src/user/user.constant';
import { ENUM_ROLE_STATUS_CODE_ERROR } from 'src/role/role.constant';
import { Response as ResExp, Request as ReqExp } from 'express';
@Controller('/auth')
export class AuthController {
    constructor(
        @Debugger() private readonly debuggerService: DebuggerService,
        private readonly authService: AuthService,
        private readonly userService: UserService,
        private readonly loggerService: LoggerService
    ) {}

    @Response('auth.me', ENUM_AUTH_STATUS_CODE_SUCCESS.AUTH_ME_SUCCESS)
    @HttpCode(HttpStatus.OK)
    @AuthJwtGuard()
    @Get('/me')
    async me(@Req() req: ReqExp) {
        console.log(req);
        return req.user;
    }

    @Response('auth.login', ENUM_AUTH_STATUS_CODE_SUCCESS.AUTH_LOGIN_SUCCESS)
    @HttpCode(HttpStatus.OK)
    @Post('/login')
    async login(
        @Body(RequestValidationPipe) data: AuthLoginValidation,
        @Res({ passthrough: true }) response: ResExp
    ): Promise<IResponse> {
        const rememberMe: boolean = data.rememberMe;
        const user: IUserDocument = await this.userService.findOne<IUserDocument>(
            {
                email: data.email
            },
            { populate: true }
        );

        if (!user) {
            this.debuggerService.error('Authorized error user not found', {
                class: 'AuthController',
                function: 'login'
            });

            throw new NotFoundException({
                statusCode:
                    ENUM_AUTH_STATUS_CODE_ERROR.AUTH_USER_NOT_FOUND_ERROR,
                message: 'auth.error.userNotFound'
            });
        } else if (!user.isActive) {
            this.debuggerService.error('Auth Block', {
                class: 'AuthController',
                function: 'refresh'
            });

            throw new UnauthorizedException({
                statusCode: ENUM_USER_STATUS_CODE_ERROR.USER_IS_INACTIVE,
                message: 'http.clientError.unauthorized'
            });
        } else if (!user.role.isActive) {
            throw new ForbiddenException({
                statusCode: ENUM_ROLE_STATUS_CODE_ERROR.ROLE_IS_INACTIVE,
                message: 'http.clientError.forbidden'
            });
        }

        const validate: boolean = await this.authService.validateUser(
            data.password,
            user.password
        );

        if (!validate) {
            this.debuggerService.error('Authorized error', {
                class: 'AuthController',
                function: 'login'
            });

            throw new BadRequestException({
                statusCode:
                    ENUM_AUTH_STATUS_CODE_ERROR.AUTH_PASSWORD_NOT_MATCH_ERROR,
                message: 'auth.error.passwordNotMatch'
            });
        }

        const safe: UserLoginTransformer = await this.userService.mapLogin(
            user
        );

        const payload: Record<string, any> = {
            ...classToPlain(safe),
            rememberMe
        };
        const accessToken: string = await this.authService.createAccessToken(
            payload,
            rememberMe
        );

        const refreshToken: string = await this.authService.createRefreshToken(
            payload,
            rememberMe
        );

        await this.loggerService.info(
            ENUM_LOGGER_ACTION.LOGIN,
            `${user._id} do login`,
            user._id,
            ['login', 'withEmail']
        );

        response.cookie('access-cookie', accessToken,{ httpOnly:true, secure: true });
        response.cookie('refresh-cookie', refreshToken,{ httpOnly:true, secure: true });

        return {
            accessToken,
            refreshToken
        };
    }

    @Response('auth.login', ENUM_AUTH_STATUS_CODE_SUCCESS.AUTH_LOGOUT_SUCCESS)
    @HttpCode(HttpStatus.OK)
    @Get('/logout')
    async logout(@Res({ passthrough: true }) response: ResExp) {
        response.cookie('access-cookie', null,{ httpOnly:true, secure: true, expires: new Date(Date.now()) });
        response.cookie('refresh-cookie', null,{ httpOnly:true, secure: true, expires: new Date(Date.now()) });
        return;
    }

    @Response('auth.refresh')
    @AuthJwtRefreshGuard()
    @HttpCode(HttpStatus.OK)
    @Post('/refresh')
    async refresh(@User() payload: Record<string, any>, @Res({ passthrough: true }) response: ResExp): Promise<IResponse> {
        const { _id, rememberMe } = payload;
        const user: IUserDocument = await this.userService.findOneById<IUserDocument>(
            _id,
            { populate: true }
        );

        if (!user.isActive) {
            this.debuggerService.error('Auth Block', {
                class: 'AuthController',
                function: 'refresh'
            });

            throw new UnauthorizedException({
                statusCode: ENUM_USER_STATUS_CODE_ERROR.USER_IS_INACTIVE,
                message: 'http.clientError.unauthorized'
            });
        } else if (!user.role.isActive) {
            throw new ForbiddenException({
                statusCode: ENUM_ROLE_STATUS_CODE_ERROR.ROLE_IS_INACTIVE,
                message: 'http.clientError.forbidden'
            });
        }

        const safe: UserLoginTransformer = await this.userService.mapLogin(
            user
        );
        const newPayload: Record<string, any> = {
            ...classToPlain(safe),
            rememberMe
        };

        const accessToken: string = await this.authService.createAccessToken(
            newPayload,
            rememberMe
        );

        const refreshToken: string = await this.authService.createRefreshToken(
            newPayload,
            rememberMe
        );

        response.cookie('access-cookie', accessToken,{ httpOnly:true, secure: true });
        response.cookie('refresh-cookie', refreshToken,{ httpOnly:true, secure: true });

        return {
            accessToken,
            refreshToken
        };
    }
}
