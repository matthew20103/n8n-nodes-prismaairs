import {
  INodeType,
  INodeTypeDescription,
  IHttpRequestOptions,
  IHttpRequestMethods,
  IHttpRequestUrl,
  NodePropertyTypes,
  ICredentialType,
  INodeProperties,
  IExecuteFunctions,
} from 'n8n-workflow';

// Define the description of the PrismaAIRS Prompt Check node
export class PrismaAIRSPromptCheck implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'Prisma AIRS Prompt Check',
    name: 'prismaAIRSPromptCheck',
    icon: 'file:prismaAIRS.svg', // Assuming you'll add an SVG icon
    group: ['transform'],
    version: 1,
    description: 'Palo Alto Networks AIRS node for checking user prompts for security issues.',
    defaults: {
      name: 'Prisma AIRS Prompt Check',
    },
    inputs: ['main'],
    outputs: ['main'],
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
        displayName: 'Chat Input (Prompt)',
        name: 'chatInput',
        type: 'string',
        default: '',
        description: 'The user\'s prompt text to be checked.',
        placeholder: '{{ $json.chatInput }}',
        required: true,
      },
      {
        displayName: 'AI Profile Name',
        name: 'aiProfileName',
        type: 'string',
        default: 'Demo-Profile-for-Input',
        description: 'The AI profile name configured in Prisma AIRS for input scanning.',
        placeholder: 'Demo-Profile-for-Input',
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
        description: 'Context for the prompt, used by AIRS for contextual analysis.',
        placeholder: 'only talk about Palo Alto networks equipment',
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
      const aiModelName = this.getNodeParameter('aiModelName', itemIndex) as string;
      const context = this.getNodeParameter('context', itemIndex) as string;

      const credentials = await this.getCredentials('prismaAIRSCredential') as ICredentialType;
      const apiKey = credentials.apiKey as string;

      const requestOptions: IHttpRequestOptions = {
        method: 'POST' as IHttpRequestMethods,
        url: 'https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request' as IHttpRequestUrl,
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
              prompt: chatInput,
              context: context,
            },
          ],
        },
        json: true, // Automatically parse JSON response
      };

      try {
        const response = await this.httpRequest(requestOptions);

        // Process the AIRS response
        let action = 'allow'; // Default action
        let outputMessage = '';

        const promptDetected = response?.result?.prompt_detected;

        if (promptDetected) {
          if (promptDetected.agent === true) {
            action = 'block';
            outputMessage = 'Palo Alto Networks AIRS detected an Agent Attack. Please redefine your questions';
          } else if (promptDetected.dlp === true) {
            action = 'block';
            outputMessage = 'Palo Alto Networks AIRS detected that there is sensitive data in your request, please try again with another question';
          } else if (promptDetected.injection === true) {
            action = 'block';
            outputMessage = 'Palo Alto Networks AIRS detected a Prompt Injection Attack. Please redefine your questions';
          } else if (promptDetected.toxic_content === true) {
            action = 'block';
            outputMessage = 'Palo Alto Networks AIRS detected some unacceptable content. Please redefine your questions';
          } else if (promptDetected.url_cats === true) {
            action = 'block';
            outputMessage = 'Palo Alto Networks AIRS detected unacceptable URL. Please redefine your questions';
          }
        }

        if (action === 'allow') {
          // If allowed, return original inputs to continue the workflow
          returnData.push({
            json: {
              sessionId: sessionId,
              action: action,
              chatInput: chatInput,
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
      } catch (error) {
        // Handle API call errors
        console.error('Prisma AIRS API Error:', error);
        returnData.push({
          json: {
            output: `Error calling Prisma AIRS API: ${error.message || 'Unknown error'}`,
          },
        });
      }
    }
    return this.helpers.returnJsonArray(returnData);
  }
}
