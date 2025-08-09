import { 
	INodeType, 
	INodeTypeDescription, 
	NodeConnectionType,
	IExecuteFunctions,
	IHttpRequestOptions,
	IHttpRequestMethods,
} from 'n8n-workflow';

export class PrismaAIRSCheck implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Prisma AIRS',
		name: 'prismaairs',
		icon: 'file:prismaAIRS.svg',
		group: ['transform'],
		version: 1,
		description: 'Prisma AIRS AI Security.',
		defaults: {
			name: 'Prisma AIRS AI Runtime Protection',
		},
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		credentials: [
			{
				name: 'prismaAIRSApi',
				required: true,
			},
		],
		requestDefaults: {
			baseURL: '={{$credentials.host}}',
			url: '/request',
		},
		properties: [
			{
				displayName: 'Session ID',
				name: 'sessionId',
				type: 'string',
				default: '{{ $json.sessionId }}',
				description: 'Unique identifier for the current chat session.',
				required: true,
			},
			{
				displayName: 'Prompt / Response',
				name: 'chatInput',
				type: 'string',
				default: '{{ $json.chatInput }}',
				description: 'The user\'s prompt text to be chcked',
				required: true,
			},
			{
				displayName: 'Prisma AIRS AI Profile Name',
				name: 'aiProfileName',
				type: 'string',
				default: 'Demo-Profile-for-Input',
				description: 'The Prisma AIRS AI profile name configured for input scanning.',
				required: true,
			},
		],
	};
	
	async execute(this: IExecuteFunctions): Promise<any> {
    const items = this.getInputData();
    const returnData: any[] = [];

    for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
      const sessionId = this.getNodeParameter('sessionId', itemIndex) as string;
      const chatInput = this.getNodeParameter('chatInput', itemIndex) as string;
      const aiProfileName = this.getNodeParameter('aiProfileName', itemIndex) as string;

      const credentials = await this.getCredentials('prismaAIRSApi') as { apiKey: string };
      const apiKey = credentials.apiKey;

      const requestOptions: IHttpRequestOptions = {
        method: 'POST' as IHttpRequestMethods,
        url: 'https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request',
        headers: {
          'Content-Type': 'application/json',
          'x-pan-token': apiKey,
        },
        body: {
          tr_id: sessionId,
          ai_profile: {
            profile_name: aiProfileName,
          },
          metadata: {
            app_name: 'n8n',
            app_user: sessionId,
          },
          contents: [
            {
              prompt: chatInput,
            },
          ],
        },
        json: true, // Automatically parse JSON response
      };

      try {
        // Fixed: Use this.helpers.httpRequest
        const response = await this.helpers.httpRequest(requestOptions);

        // Process the AIRS response
				const action = response.result.action;
				let outputMessage = '';
				switch (action) {
					case 'allow':
						returnData.push({
							sessionId: sessionId,
							chatInput: chatInput,
						});
						break;
					case 'malicious':
						outputMessage = 'Palo Alto Networks AIRS detected a Prompt Injection.';
						returnData.push({
            json: {
              output: outputMessage,
            },
          });
						break;
					default:
						returnData.push({
							sessionId: sessionId,
							chatInput: chatInput,
						});
				}	
        
      } catch (error: unknown) { // Fixed: Explicitly type error as unknown
        // Handle API call errors
        console.error('Prisma AIRS API Error:', error);
        returnData.push({
          json: {
            output: `Error calling Prisma AIRS API: ${(error as Error).message || 'Unknown error'}`, // Fixed: Cast error to Error
          },
        });
      }
    }
    return this.helpers.returnJsonArray(returnData);
  }
	
}
