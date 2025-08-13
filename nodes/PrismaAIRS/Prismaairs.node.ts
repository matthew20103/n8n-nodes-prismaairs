import { 
	INodeType, 
	INodeTypeDescription, 
	NodeConnectionType,
	IExecuteFunctions,
	IHttpRequestOptions,
	IHttpRequestMethods,
	INodeExecutionData,
} from 'n8n-workflow';

export class Prismaairs implements INodeType {
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
						action: 'Prisma AIRS prompt inspection',
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
						action: 'Prisma AIRS response inspection',
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
						action: 'Prisma AIRS inspection result',
						description: 'Inspection Result for Block Action',
						routing: {
							request: {
								method: 'POST',
								url: '=/request',
							},
						},
					},
				],
				default: 'Prisma AIRS Prompt Inspection',
			},

			{
				displayName: 'Prompt (Required)',
				name: 'chatInput',
				type: 'string',
				default: '={{ $json.chatInput }}',
				description: 'The user\'s prompt text to be checked',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection'],
					},
				},
			},
			{
				displayName: 'Response (Required)',
				name: 'outPut',
				type: 'string',
				default: '={{ $json.output }}',
				description: 'The AI Agent\'s response text to be checked',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Response Inspection'],
					},
				},
			},
			{
				displayName: 'Prisma AIRS AI Profile for Input (Required)',
				name: 'aiProfileNameInput',
				type: 'string',
				default: 'Demo-Profile-for-Input',
				description: 'The Prisma AIRS AI profile name configured for input scanning',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection'],
					},
				},
			},
			{
				displayName: 'Prisma AIRS AI Profile for Output (Required)',
				name: 'aiProfileNameOutput',
				type: 'string',
				default: 'Demo-Profile-for-Output',
				description: 'The Prisma AIRS AI profile name configured for output scanning',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Response Inspection'],
					},
				},
			},
			{
				displayName: 'Session ID (Optional)',
				name: 'sessionId',
				type: 'string',
				default: '={{ $json.sessionId }}',
				description: 'Unique identifier for the current chat session',
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection', 'Prisma AIRS Response Inspection'],
					},
				},
			},
			{
				displayName: 'App User (Optional)',
				name: 'appUser',
				type: 'string',
				default: '',
				description: 'User name for the current chat session',
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection', 'Prisma AIRS Response Inspection'],
					},
				},
			},
			{
				displayName: 'User IP (Optional)',
				name: 'userIP',
				type: 'string',
				default: '',
				description: 'User IP address for the current chat session',
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection', 'Prisma AIRS Response Inspection'],
					},
				},
			},
			{
				displayName: 'App Name (Optional)',
				name: 'appName',
				type: 'string',
				default: '',
				description: 'Application name for the current chat session',
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection', 'Prisma AIRS Response Inspection'],
					},
				},
			},
			{
				displayName: 'AI Model Name (Optional)',
				name: 'aiModel',
				type: 'string',
				default: '',
				description: 'AI Model name for the current chat session',
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection', 'Prisma AIRS Response Inspection'],
					},
				},
			},
			{
				displayName: 'Custom Your Block Message',
				name: 'promptInjectionAttackMessage',
				type: 'string',
				default: 'Palo Alto Networks Prisma AIRS detected an attack. Please redefine your questions.',
				description: 'The message output when Prompt Injection attack is detected',
				required: true,
				typeOptions: {rows: 3},
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Inspection Result'],
					},
				},
			},
		],
	};
	
	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];

		if (items[0].json.hasOwnProperty('prismaAIRSAction')) {
			if (items[0].json.hasOwnProperty('output')) {
				const prismaAIRSAction = items[0].json.prismaAIRSAction;
				const message = items[0].json.output;
					switch (prismaAIRSAction) {
						case 'allow':
							returnData.push({
								json: {
									output: message,
								}
							});
							return this.prepareOutputData(returnData);
							break;
						case 'block':
							const messageBlocked = this.getNodeParameter('promptInjectionAttackMessage', 0) as string;
							returnData.push({
								json: {
									output: messageBlocked,
								}
							});
							return this.prepareOutputData(returnData);
							break;
						default:
							returnData.push({
								json: {
									output: message,
									action: 'default',
								}
							});
							return this.prepareOutputData(returnData);
						}
			}

			if (items[0].json.hasOwnProperty('chatInput')) {
				const prismaAIRSAction = items[0].json.prismaAIRSAction;
				const message = items[0].json.chatInput;
				const sessionId = items[0].json.sessionId;
				
				switch (prismaAIRSAction) {
					case 'allow':
							// For the case of handling Prisma AIRS Prompt Inspection, return both sessionId and chatInput as json keys.
							returnData.push({
								json: {
									sessionId: sessionId,
									chatInput: message,
								}
							});
						return this.prepareOutputData(returnData);
						break;
					// For the case where AI attack is found, return the block message to json key output.
					case 'block':
							const messageBlocked = this.getNodeParameter('promptInjectionAttackMessage', 0) as string;
							returnData.push({
								json: {
									output: messageBlocked,
								}
							});
						return this.prepareOutputData(returnData);
						break;
						// For unknown issue
					default:
						returnData.push({
								json: {
									output: 'Unknown issue.',
								}
							});
						return this.prepareOutputData(returnData);
				}
			}
		}

		// Prisma AIRS Response Inspection
    if (items[0].json.hasOwnProperty('output')) {
				for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
					const sessionId = this.getNodeParameter('sessionId', itemIndex) as string;
		      const outPut = this.getNodeParameter('outPut', itemIndex) as string;
		      const aiProfileNameOutput = this.getNodeParameter('aiProfileNameOutput', itemIndex) as string;
					const appUser = this.getNodeParameter('appUser', itemIndex) as string;
					const userIP = this.getNodeParameter('userIP', itemIndex) as string;
					const appName = this.getNodeParameter('appName', itemIndex) as string;
					const aiModel = this.getNodeParameter('aiModel', itemIndex) as string;
		
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
		            profile_name: aiProfileNameOutput,
		          },
		          metadata: {
		            app_name: appName,
		            app_user: appUser,
								ai_model: aiModel,
								user_ip: userIP,
		          },
		          contents: [
		            {
		              response: outPut,
		            },
		          ],
		        },
		        json: true, // Automatically parse JSON response
	      	};
	
	      try {
	        // Pass message to Prisma AIRS API Intercept for inspection
	        const response = await this.helpers.httpRequest(requestOptions);
	
	        // Process the AIRS response
					const action = response.action;
					const response_detected = response.prompt_detected;
					returnData.push({
							json: {
								output: outPut,
								prismaAIRSAction: action,
								response_detected: response_detected,
							}
					});
					return this.prepareOutputData(returnData);
	        
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
		}

		if (items[0].json.hasOwnProperty('chatInput')) {
			for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
				const sessionId = this.getNodeParameter('sessionId', itemIndex) as string;
	      const chatInput = this.getNodeParameter('chatInput', itemIndex) as string;
	      const aiProfileNameInput = this.getNodeParameter('aiProfileNameInput', itemIndex) as string;
				const appUser = this.getNodeParameter('appUser', itemIndex) as string;
				const userIP = this.getNodeParameter('userIP', itemIndex) as string;
				const appName = this.getNodeParameter('appName', itemIndex) as string;
				const aiModel = this.getNodeParameter('aiModel', itemIndex) as string;
	
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
	            profile_name: aiProfileNameInput,
	          },
	          metadata: {
	            app_name: appName,
	            app_user: appUser,
							ai_model: aiModel,
							user_ip: userIP,
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
	        // Pass message to Prisma AIRS API Intercept for inspection
	        const response = await this.helpers.httpRequest(requestOptions);
	
	        // Process the AIRS response
					const action = response.action;
					const prompt_detected = response.prompt_detected;
					returnData.push({
							json: {
								sessionId: sessionId,
								chatInput: chatInput,
								prismaAIRSAction: action,
								prompt_detected: prompt_detected,
							}
					});
					return this.prepareOutputData(returnData);
	        
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
		}
    return this.prepareOutputData(returnData);
  }
	
}
