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
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Prompt Inspection'],
					},
				},
			},
			{
				displayName: 'Prompt',
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
				displayName: 'Response',
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
				displayName: 'Prisma AIRS AI Profile for Input',
				name: 'aiProfileNameInput',
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
			{
				displayName: 'Prisma AIRS AI Profile for Output',
				name: 'aiProfileNameOutput',
				type: 'string',
				default: 'Demo-Profile-for-Output',
				description: 'The Prisma AIRS AI profile name configured for output scanning.',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Response Inspection'],
					},
				},
			},

			{
				displayName: 'AI Agent Attack Message',
				name: 'aiAgentAttackMessage',
				type: 'string',
				default: 'Palo Alto Networks Prisma AIRS detected an attack. Please redefine your questions.',
				description: 'The message output when AI Agent attack is detected.',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Inspection Result'],
					},
				},
			},
			{
				displayName: 'Prompt Injection Attack Message',
				name: 'promptInjectionAttackMessage',
				type: 'string',
				default: 'Palo Alto Networks Prisma AIRS detected an attack. Please redefine your questions.',
				description: 'The message output when Prompt Injection attack is detected.',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Inspection Result'],
					},
				},
			},
			{
				displayName: 'Toxic Content Message',
				name: 'toxicContentMessage',
				type: 'string',
				default: 'Palo Alto Networks Prisma AIRS detected an attack. Please redefine your questions.',
				description: 'The message output when Toxic Content is detected.',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Inspection Result'],
					},
				},
			},
			{
				displayName: 'Malicious Code Message',
				name: 'maliciousCodeMessage',
				type: 'string',
				default: 'Palo Alto Networks Prisma AIRS detected an attack. Please redefine your questions.',
				description: 'The message output when Malicious Code is detected.',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Inspection Result'],
					},
				},
			},
			{
				displayName: 'Malicious URL Message',
				name: 'maliciousURLMessage',
				type: 'string',
				default: 'Palo Alto Networks Prisma AIRS detected an attack. Please redefine your questions.',
				description: 'The message output when Malicious URL is detected.',
				required: true,
				displayOptions: {
					show: {
						operation: ['Prisma AIRS Inspection Result'],
					},
				},
			},
			{
				displayName: 'DLP Message',
				name: 'dlpMessage',
				type: 'string',
				default: 'Palo Alto Networks Prisma AIRS detected a Sensitive Data Leakage. Please redefine your questions.',
				description: 'The message output when Sensitive Data is detected.',
				required: true,
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
							let messageBlocked = this.getNodeParameter('promptInjectionAttackMessage', 0) as string;
							interface PromptDetected {
	       			 	agent?: string;
	        			injection?: string;
				        toxic_content?: string;
				        malicious_code?: string;
				        url_cats?: string;
				        dlp?: string;
				    	}
							const promptDetected = items[0].json.prompt_detected;
							if (promptDetected && typeof promptDetected === 'object') {
								const parsedPrompt = promptDetected as PromptDetected;
								if (parsedPrompt.agent === 'true') {
									messageBlocked = this.getNodeParameter('aiAgentAttackMessage', 0) as string;
								} else if (parsedPrompt.injection === 'true') {
									messageBlocked = this.getNodeParameter('promptInjectionAttackMessage', 0) as string;
								} else if (parsedPrompt.toxic_content === 'true') {
									messageBlocked = this.getNodeParameter('toxicContentMessage', 0) as string;
								} else if (parsedPrompt.malicious_code === 'true') {
									messageBlocked = this.getNodeParameter('maliciousCodeMessage', 0) as string;
								} else if (parsedPrompt.url_cats === 'true') {
									messageBlocked = this.getNodeParameter('maliciousURLMessage', 0) as string;
								} else if (parsedPrompt.dlp === 'true') {
									messageBlocked = this.getNodeParameter('dlpMessage', 0) as string;
								} else {
									messageBlocked = parsedPrompt.toxic_content as string;
								}
							}
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
							let messageBlocked = this.getNodeParameter('promptInjectionAttackMessage', 0) as string;
							interface PromptDetected {
	       			 	agent?: string;
	        			injection?: string;
				        toxic_content?: string;
				        malicious_code?: string;
				        url_cats?: string;
				        dlp?: string;
				    	}
							const promptDetected = items[0].json.prompt_detected;
							if (promptDetected && typeof promptDetected === 'object') {
								const parsedPrompt = promptDetected as PromptDetected;
								if (parsedPrompt.agent === 'true') {
									messageBlocked = this.getNodeParameter('aiAgentAttackMessage', 0) as string;
								} else if (parsedPrompt.injection === 'true') {
									messageBlocked = this.getNodeParameter('promptInjectionAttackMessage', 0) as string;
								} else if (parsedPrompt.toxic_content === 'true') {
									messageBlocked = this.getNodeParameter('toxicContentMessage', 0) as string;
								} else if (parsedPrompt.malicious_code === 'true') {
									messageBlocked = this.getNodeParameter('maliciousCodeMessage', 0) as string;
								} else if (parsedPrompt.url_cats === 'true') {
									messageBlocked = this.getNodeParameter('maliciousURLMessage', 0) as string;
								} else if (parsedPrompt.dlp === 'true') {
									messageBlocked = this.getNodeParameter('dlpMessage', 0) as string;
								} else {
									messageBlocked = parsedPrompt.agent as string;
								}
							}
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
	      const outPut = this.getNodeParameter('outPut', itemIndex) as string;
	      const aiProfileNameOutput = this.getNodeParameter('aiProfileNameOutput', itemIndex) as string;
	
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
	          tr_id: '',
	          ai_profile: {
	            profile_name: aiProfileNameOutput,
	          },
	          metadata: {
	            app_name: 'n8n',
	            app_user: 'AI Agent',
	          },
	          contents: [
	            {
	              prompt: outPut,
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
								output: outPut,
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

		if (items[0].json.hasOwnProperty('chatInput')) {
			for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
				const sessionId = this.getNodeParameter('sessionId', itemIndex) as string;
	      const chatInput = this.getNodeParameter('chatInput', itemIndex) as string;
	      const aiProfileNameInput = this.getNodeParameter('aiProfileNameInput', itemIndex) as string;
	
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
