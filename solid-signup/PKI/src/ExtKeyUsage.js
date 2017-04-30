import * as asn1js from "asn1js";
import { getParametersValue } from "pvutils";
//**************************************************************************************
/**
 * Class from RFC5280
 */
export default class ExtKeyUsage
{
	//**********************************************************************************
	/**
	 * Constructor for ExtKeyUsage class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<string>}
		 * @description keyPurposes
		 */
		this.keyPurposes = getParametersValue(parameters, "keyPurposes", ExtKeyUsage.defaultValues("keyPurposes"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "keyPurposes":
				return [];
			default:
				throw new Error(`Invalid member name for ExtKeyUsage class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// ExtKeyUsage OID ::= 2.5.29.37
		//
		// ExtKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

		// KeyPurposeId ::= OBJECT IDENTIFIER

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [keyPurposes]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new asn1js.Sequence({
			name: (names.blockName || ""),
			value: [
				new asn1js.Repeated({
					name: (names.keyPurposes || ""),
					value: new asn1js.ObjectIdentifier()
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = asn1js.compareSchema(schema,
			schema,
			ExtKeyUsage.schema({
				names: {
					keyPurposes: "keyPurposes"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for ExtKeyUsage");
		//endregion

		//region Get internal properties from parsed schema
		this.keyPurposes = Array.from(asn1.result.keyPurposes, element => element.valueBlock.toString());
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new asn1js.Sequence({
			value: Array.from(this.keyPurposes, element => new asn1js.ObjectIdentifier({ value: element }))
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			keyPurposes: Array.from(this.keyPurposes)
		};
	}
	//**********************************************************************************
}
//**************************************************************************************
