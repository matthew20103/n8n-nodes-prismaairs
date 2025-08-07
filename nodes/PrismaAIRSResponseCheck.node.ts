import {
  INodeType,
  INodeTypeDescription,
  IHttpRequestOptions,
  IHttpRequestMethods,
  NodePropertyTypes,
  NodeConnectionType, // Added NodeConnectionType import
  IExecuteFunctions,
} from 'n8n-workflow';

// Define the description of the PrismaAIRS Response Check node
export class PrismaAIRSResponseCheck implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'Prisma AIRS Response Check',
    name: 'prismaAIRSResponseCheck',
    icon: 'file:prismaAIRS.svg', // Assuming you'll add an SVG icon
    group: ['transform'],
    version: 1,
    description: 'Palo Alto Networks AIRS node for checking AI model responses for security issues.',
    defaults: {
      name: 'Prisma AIRS Response Check',
    },
    inputs: [NodeConnectionType.Main], // Fixed: Changed to NodeConnectionType.Main
    outputs: [NodeConnectionType.Main], // Fixed: Changed to NodeConnectionType.Main
    credentials: [
      {
        name: 'prismaAIRSCredential',
        required: true,
      },
    ],
    properties: [
      {
        displayName: 'Session ID',
        name: 'sessionId',
        type: 'string',
        default: '',
        description: 'Unique identifier for the current chat session.',
        placeholder: '{{ $json.sessionId }}',
        required: true,
      },
      {
        displayName: 'AI Output (Response)',
        name: 'aiOutput',
        type: 'string',
        default: '',
        description: 'The AI model\'s response text to be checked.',
        placeholder: '{{ $json.output }}',
        required: true,
      },
      {
        displayName: 'AI Profile Name',
        name: 'aiProfileName',
        type: 'string',
        default: 'Demo-Profile-for-Output',
        description: 'The AI profile name configured in Prisma AIRS for output scanning.',
        placeholder: 'Demo-Profile-for-Output',
      },
      {
        displayName: 'AI Model Name',
        name: 'aiModelName',
        type: 'string',
        default: 'Claude-3.5',
        description: 'The name of the AI model being used.',
        placeholder: 'Claude-3.5',
      },
      {
        displayName: 'Context',
        name: 'context',
        type: 'string',
        default: 'only talk about Palo Alto networks equipment',
        description: 'Context for the response, used by AIRS for contextual analysis.',
        placeholder: 'only talk about Palo Alto networks equipment',
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<any> {
    const items = this.getInputData();
    const returnData: any[] = [];

    for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
      const sessionId = this.getNodeParameter('sessionId', itemIndex) as string;
      const aiOutput = this.getNodeParameter('aiOutput', itemIndex) as string;
      const aiProfileName = this.getNodeParameter('aiProfileName', itemIndex) as string;
      const aiModelName = this.getNodeParameter('aiModelName', itemIndex) as string;
      const context = this.getNodeParameter('context', itemIndex) as string;

      // Fixed: Explicitly cast credentials to ensure apiKey property is recognized
      const credentials = await this.getCredentials('prismaAIRSCredential') as { apiKey: string };
      const apiKey = credentials.apiKey;

      const requestOptions: IHttpRequestOptions = {
        method: 'POST' as IHttpRequestMethods,
        url: 'https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request', // Removed IHttpRequestUrl type
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey, // Use the API key from credentials
        },
        body: {
          tr_id: sessionId,
          ai_profile: {
            profile_name: aiProfileName,
          },
          metadata: {
            app_name: 'n8n',
            app_user: sessionId,
            ai_model: aiModelName,
          },
          contents: [
            {
              response: aiOutput, // Note: 'response' for output checking
              context: context,
            },
          ],
        },
        json: true, // Automatically parse JSON response
      };

      try {
        // Fixed: Use this.helpers.httpRequest
        const response = await this.helpers.httpRequest(requestOptions);

        // Process the AIRS response
        let action = 'allow'; // Default action
        let outputMessage = '';

        const responseDetected = response?.result?.response_detected;

        if (responseDetected) {
          if (responseDetected.db_security === true) {
            action = 'block';
            outputMessage = 'Palo Alto Networks AIRS detected a database security issue in the response. Please redefine your questions';
          } else if (responseDetected.dlp === true) {
            action = 'block';
            outputMessage = 'Palo Alto Networks AIRS detected that there is sensitive data in the response, please try again with another question';
          } else if (responseDetected.ungrounded === true) {
            action = 'block';
            outputMessage = 'Palo Alto Networks AIRS detected an off topic response. Please redefine your questions';
          } else if (responseDetected.toxic_content === true) {
            action = 'block';
            outputMessage = 'Palo Alto Networks AIRS detected some unacceptable content in the response. Please redefine your questions';
          } else if (responseDetected.url_cats === true) {
            action = 'block';
            outputMessage = 'Palo Alto Networks AIRS detected unacceptable URL in the response. Please redefine your questions';
          }
        }

        if (action === 'allow') {
          // If allowed, return original output to continue the workflow
          returnData.push({
            json: {
              output: aiOutput,
            },
          });
        } else {
          // If blocked, return the error message
          returnData.push({
            json: {
              output: outputMessage,
            },
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
