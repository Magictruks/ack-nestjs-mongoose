import { applyDecorators, UsePipes } from '@nestjs/common';
import { MessagePattern, Transport } from '@nestjs/microservices';
import { ClassConstructor } from 'class-transformer';
import { IAuthApplyDecorator } from 'src/auth/auth.interface';
import { RequestKafkaValidationPipe } from 'src/request/pipe/request.kafka.validation.pipe';

export function KafkaRequest(
    topic: string,
    validation?: ClassConstructor<unknown>
): IAuthApplyDecorator {
    if (validation) {
        return applyDecorators(
            MessagePattern(topic, Transport.KAFKA),
            UsePipes(RequestKafkaValidationPipe(validation))
        );
    }

    return applyDecorators(MessagePattern(topic, Transport.KAFKA));
}
