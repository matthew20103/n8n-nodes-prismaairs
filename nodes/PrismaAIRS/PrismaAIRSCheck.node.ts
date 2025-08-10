import { 
	INodeType, 
	INodeTypeDescription, 
	NodeConnectionType,
	IExecuteFunctions,
	IHttpRequestOptions,
	IHttpRequestMethods,
	INodeExecutionData,
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
				displayName: 'Resource',
				name: 'resource',
				type: 'hidden',
				noDataExpression: true,
				options: [
					{
						name: 'Default',
						value: 'Default',
						description: '',
					},
				],
				default: '',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['Default'],
					},
				},
				options: [
					{
						name: 'Prisma AIRS Prompt Inspection',
						value: 'Prisma AIRS Prompt Inspection',
						action: 'Prisma AIRS Prompt Inspection',
						description: 'Prompt Protection Node',
						routing: {
							request: {
								method: 'POST',
								url: '=/request',
							},
						},
					},
					{
						name: 'Prisma AIRS Response Inspection',
						value: 'Prisma AIRS Response Inspection',
						action: 'Prisma AIRS Response Inspection',
						description: 'Response Protection Node',
						routing: {
							request: {
								method: 'POST',
								url: '=/request',
							},
						},
					},
					{
						name: 'Prisma AIRS Inspection Result',
						value: 'Prisma AIRS Inspection Result',
						action: 'Prisma AIRS Inspection Result',
						description: 'Inspection Result for Block Action',
						routing: {
							request: {
								method: 'POST',
								url: '=/request',
							},
						},
					},
				],
				default: '',
			},
			
			{
				displayName: 'Session ID',
				name: 'sessionId',
				type: 'string',
				default: '={{ $json.sessionId }}',
				description: 'Unique identifier for the current chat session.',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection'],
					},
				},
			},
			{
				displayName: 'Prompt / Response',
				name: 'chatInput',
				type: 'string',
				default: '={{ $json.chatInput }}',
				description: 'The user\'s prompt text to be chcked',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection', 'Prisma AIRS Response Inspection'],
					},
				},
			},
			{
				displayName: 'Prisma AIRS AI Profile Name',
				name: 'aiProfileName',
				type: 'string',
				default: 'Demo-Profile-for-Input',
				description: 'The Prisma AIRS AI profile name configured for input scanning.',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection'],
					},
				},
			},
		],
	};
	
	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];

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
				const action = response.action;
				returnData.push({
	            json: {
	              'action': action,
	            },
	          });
				let outputMessage = '';
				switch (action) {
					case 'allow':
						returnData.push({
							json: {
								sessionId: sessionId,
								chatInput: chatInput,
							}
						});
						break;
					case 'block':
						outputMessage = 'Palo Alto Networks AIRS detected a Prompt Injection.';
						console.error(outputMessage)
						return [[]];
						break;
					default:
						returnData.push({
							json: {
								sessionId: sessionId,
								chatInput: chatInput,
								'default': 'This is default case.',
							}
						});
				}	
        
      } catch (error: unknown) {
			    let errorMessage = 'Unknown error';
			    if (error instanceof Error) {
			        // If the error is a standard Error object, use its message
			        errorMessage = error.message;
			    } else if (typeof error === 'object' && error !== null) {
			        // If it's an object, stringify it to see its contents
			        errorMessage = JSON.stringify(error);
			    } else {
			        // Otherwise, just use its string representation
			        errorMessage = String(error);
			    }
			
			    console.error('Prisma AIRS API Error:', errorMessage);
			    returnData.push({
			        json: {
			            output: `Error calling Prisma AIRS API: ${errorMessage}`,
			        },
			    });
			}
		}
    return this.prepareOutputData(returnData);
  }
	
}
