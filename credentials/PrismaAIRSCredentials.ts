import {
  ICredentialType,
  INodeProperties,
} from 'n8n-workflow';

export class PrismaAIRSCredential implements ICredentialType {
  name = 'prismaAIRSCredential';
  displayName = 'Prisma AIRS API';
  properties: INodeProperties[] = [
    {
      displayName: 'API Key',
      name: 'apiKey',
      type: 'string',
      typeOptions: { password: true },
      default: '',
      required: true,
      description: 'Your Palo Alto Networks AIRS API Key.',
    },
  ];
}
