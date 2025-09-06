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
						name: 'Prisma AIRS Prompt Result',
						value: 'Prisma AIRS Prompt Result',
						action: 'Prisma AIRS prompt result',
						description: 'Prompt Inspection Result for Block Action',
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
				default: '={{ $json.chatInput || $json.body.prompt }}',
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
				default: '={{ $json.sessionId || null }}',
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
						operation: ['Prisma AIRS Prompt Inspection', 'Prisma AIRS Response Inspection'],
					},
				},
			},
		],
	};
	
	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		
		// Check if the input data has the property 'prismaAIRSAction'
		if (items[0].json.hasOwnProperty('prismaAIRSAction')) {

			// Handles prompt inspection result
			if (items[0].json.hasOwnProperty('chatInput')) {
				const prismaAIRSAction = items[0].json.prismaAIRSAction;
				const block_message = items[0].json.chatInput;
				const sessionId = items[0].json.sessionId;
				const prompt_detected = items[0].json.prompt_detected;
				const original_prompt= items[0].json.original_prompt;
				const prompt_detection_details = items[0].json.prompt_detection_details;
				
				switch (prismaAIRSAction) {
					// For the case where AI attack is found, return the block message to json key output.
					case 'block':
						returnData.push({
							json: {
								output: block_message,
								sessionId: sessionId,
								prismaAIRSAction: prismaAIRSAction,
								prompt_detected: prompt_detected,
								original_prompt: original_prompt,
								prompt_detection_details: prompt_detection_details,
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

			// Handles response inspection result
			if (items[0].json.hasOwnProperty('output')) {
				const output_message = items[0].json.output;

				returnData.push({
					json: {
						output: output_message,
					}
				});
				return this.prepareOutputData(returnData);
			}
		}

		// Prisma AIRS Response Inspection
		else if (items[0].json.hasOwnProperty('output')) {
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
					const action = response.action ?? 'block';
					const response_detected = response.response_detected ?? null;
					const response_masked_data = response.response_masked_data ?? null;
					const response_detection_details = response.response_detection_details ?? null;
					
					if (action === 'block') {
						const messageBlocked = this.getNodeParameter('promptInjectionAttackMessage', 0) as string;
						returnData.push({
							json: {
								sessionId: sessionId,
								output: messageBlocked,
								prismaAIRSAction: action,
								response_detected: response_detected,
								masked_response: response_masked_data?.data,
								original_response: outPut,
								response_detection_details: response_detection_details,
							}
						});
					}
					else if (response_masked_data !== null) {
						returnData.push({
							json: {
								sessionId: sessionId,
								output: response_masked_data.data,
								prismaAIRSAction: action,
								response_detected: response_detected,
								original_response: outPut,
								response_detection_details: response_detection_details,
							}
						});
					}
					else {
						returnData.push({
							json: {
								sessionId: sessionId,
								output: outPut,
								prismaAIRSAction: action,
								response_detected: response_detected,
								response_masked_data: response_masked_data,
								response_detection_details: response_detection_details,
							}
						});
					}
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

		// Prisma AIRS Prompt Inspection
		else {
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
				const action = response.action ?? 'block';
				const prompt_detected = response.prompt_detected ?? null;;
				const prompt_masked_data = response.prompt_masked_data ?? null;;
				const prompt_detection_details = response.prompt_detection_details ?? null;;
				
				if (action === 'block') {
					const messageBlocked = this.getNodeParameter('promptInjectionAttackMessage', 0) as string;
					returnData.push({
						json: {
							sessionId: sessionId,
							chatInput: messageBlocked,
							prismaAIRSAction: action,
							prompt_detected: prompt_detected,
							masked_prompt: prompt_masked_data?.data,
							original_prompt: chatInput,
							prompt_detection_details: prompt_detection_details,
						}
					});
				}
				else if (prompt_masked_data !== null) {
					returnData.push({
						json: {
							sessionId: sessionId,
							chatInput: prompt_masked_data.data,
							prismaAIRSAction: action,
							prompt_detected: prompt_detected,
							original_prompt: chatInput,
							prompt_detection_details: prompt_detection_details,
						}
					});
				}
				else {
					returnData.push({
						json: {
							sessionId: sessionId,
							chatInput: chatInput,
							prismaAIRSAction: action,
							prompt_detected: prompt_detected,
							prompt_masked_data: prompt_masked_data,
							prompt_detection_details: prompt_detection_details,
						}
					});
				}
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
