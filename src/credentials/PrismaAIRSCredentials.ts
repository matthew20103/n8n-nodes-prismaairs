import {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class PrismaAIRSCredentials implements ICredentialType {
  name = 'prismaAIRSCredentials';
  displayName = 'Prisma AIRS API';

	documentationUrl = 'https://pan.dev/airs/';
  
  properties: INodeProperties[] = [
    {
      displayName: 'API Key',
      name: 'apiKey',
      type: 'string',
      default: '',
      description: 'Your Palo Alto Networks AIRS API Key.',
    },
  ];
  authenticate = {
		type: 'generic',
		properties: {
			qs: {
				'api_key': '={{$credentials.apiKey}}'
			}
		},
	} as IAuthenticateGeneric;
}
