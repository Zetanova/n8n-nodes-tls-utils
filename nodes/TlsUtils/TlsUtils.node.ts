import { IDataObject, IExecuteFunctions, INodeExecutionData, INodeType, INodeTypeDescription } from 'n8n-workflow';
import { TlsEntry, testTls } from './helpers/utils';


export class TlsUtils implements INodeType {
	description: INodeTypeDescription = {
		displayName: "TLS Utils",
		name: "TlsUtils",
		group: ['transform'],
		icon: "file:tlsutils.svg",
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description: "retrieve and test certificate of a tls-endpoint",
		defaults: {
			name: 'TLS Utils',
		},
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			{
				displayName: 'Host',
				name: 'host',
				type: 'string',
				default: '',
				placeholder: 'Hostname or IP address',
				description: 'The address of the tls endpoint',
				hint: 'webserver1.example.com',
				required: true,
			},
			{
				displayName: 'Port',
				name: 'port',
				type: 'number',
				default: 443,
				placeholder: 'Port number',
				description: 'The port of the tls endpoint',
				hint: '443',
				required: true
			},
			{
				displayName: 'Servername',
				name: 'servername',
				type: 'string',
				default: undefined,
				placeholder: 'Server name',
				description: 'The domain name to use in the SNI header',
				hint: 'example.com',
			},
			{
				displayName: 'Additional Fields',
				name: 'additionalFields',
				type: 'collection',
				placeholder: 'Add Field',
				default: {},
				options: [
					{
						displayName: 'Grace Period',
						name: 'gracePeriod',
						type: 'number',
						default: 0.10,
						typeOptions: {
							minValue: 0,
							maxValue: 1,
							numberPrecision: 2,
						},
						description: 'Percent of certificate lifetime',
				},
				],
			}
		],

	};

	async execute(this: IExecuteFunctions) {
		const items = this.getInputData();

		const returnData: INodeExecutionData[] = [];

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {

			//const item = items[itemIndex];

			const host = this.getNodeParameter('host', itemIndex) as string;
			const port = this.getNodeParameter('port', itemIndex) as number;
			const servername = this.getNodeParameter('servername', itemIndex, '') as string;

			const additionalFields = this.getNodeParameter('additionalFields', itemIndex) as IDataObject;
			const gracePeriod = additionalFields['gracePeriod'] as number ?? 0.10;

			const entry:TlsEntry = {
				host: host,
				port: port,
				servername: servername ? servername : undefined
			}

			var result = await testTls(entry, gracePeriod)

			returnData.push({
				pairedItem: { item: itemIndex },
				json: { ... result, endpoint: { host: host, port: port } }
			});
		}

		return [returnData];
	}
}
