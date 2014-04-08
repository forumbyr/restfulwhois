package com.cnnic.whois.util;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.json.JSONArray;

import org.apache.commons.lang.StringUtils;
import org.apache.solr.client.solrj.util.ClientUtils;
import org.springframework.web.context.ContextLoader;

import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.service.QueryService;

/***
 * 
 * Whois Util
 *
 */
public class WhoisUtil {
	public static final String QUERY_TYPE = "queryType";
	public static final String QUERY_JOIN_TYPE = "queryJoinType";
	public static final String BLANKSPACE = "    ";

	public static final String FUZZY_DOMAINS = "domains";
	public static final String FUZZY_NAMESERVER = "nameservers";
	public static final String FUZZY_ENTITIES = "entities";
	public static final String IP = "ip";
	public static final String DMOAIN = "domain";
	public static final String ENTITY = "entity";
	public static final String NAMESERVER = "nameserver";

	public static final String DELEGATIONKEYS = "delegationkeys";
	public static final String DNRDOMAIN = "dnrdomain";
	public static final String DNRENTITY = "dnrentity";
	public static final String LINK = "link";
	public static final String LINKS = "links";
	public static final String AUTNUM = "autnum";
	public static final String PHONES = "phones";
	public static final String POSTALASSDESS = "postaladdress";
	public static final String RIRDOMAIN = "rirdomain";
	public static final String RIRENTITY = "rirentity";
	public static final String VARIANTS = "variants";

	public static final String NOTICES = "notices";
	public static final String PUBLICIDS = "publicIds";
	public static final String SECUREDNS = "secureDNS";
	public static final String DSDATA = "dsData";
	public static final String KEYDATA = "keyData";
	public static final String REGISTRAR = "registrar";
	public static final String SPONSOREDBY = "SponsoredBy";
	public static final String REMARKS = "remarks";
	public static final String EVENTS = "events";
	public static final String ENTITIES = "entities";
	public static final String ERRORMESSAGE = "errormessage";
	public static final String HELP = "help";
	public static final String SEARCH_RESULTS_TRUNCATED_EKEY = "searchResultsTruncated";
	public static final String RDAPCONFORMANCEKEY = "rdapConformance";
	public static final String RDAPCONFORMANCE = "rdap_level_0";

	public static final String PRX = "/";
	public static final String JNDI_NAME = "java:comp/env/jdbc/DataSource";

	public static final String SELECT_LIST_IPv4_1 = "select * from ip where StartLowAddress <=";
	public static final String SELECT_LIST_IPv4_2 = " and ";
	public static final String SELECT_LIST_IPv4_3 = " <= EndLowAddress";

	public static final String SELECT_LIST_IPv6_1 = "select * from ip where (StartHighAddress <";
	public static final String SELECT_LIST_IPv6_2 = " or (StartHighAddress = ";
	public static final String SELECT_LIST_IPv6_3 = " && StartLowAddress <= ";
	public static final String SELECT_LIST_IPv6_4 = " )) and (EndHighAddress >";
	public static final String SELECT_LIST_IPv6_5 = " or (EndhighAddress = ";
	public static final String SELECT_LIST_IPv6_6 = " and EndLowAddress >= ";
	public static final String SELECT_LIST_IPv6_7 = " )) ";

	public static final String SELECT_LIST_IPv6_8 = "select * ,EndHighAddress - StartHighAddress as high,"
			+ "EndLowAddress - StartLowAddress as low  from ip where (StartHighAddress <";
	public static final String SELECT_LIST_IPv6_9 = "order by high ,low  limit 1";

	public static final String SELECT_LIST_IPv4_4 = "select * ,StartLowAddress-EndLowAddress as se from ip where StartLowAddress <=";
	public static final String SELECT_LIST_IPv4_5 = "<= EndLowAddress order by se limit 1";

	public static final String SELECT_LIST_RIRENTITY = "select * from RIREntity where Handle=";
	public static final String SELECT_LIST_DNRENTITY = "select * from DNREntity where Handle=";
	public static final String SELECT_LIST_RIRDOMAIN = "select * from RIRDomain where Ldh_Name='%s'";
	public static final String SELECT_LIST_DNRDOMAIN = "select * from DNRDomain where Ldh_Name='%s' or unicode_name='%s'";
	public static final String SELECT_LIST_NAMESREVER = "select * from nameServer where Ldh_Name='%s' or unicode_name='%s'";
	public static final String SELECT_LIST_ERRORMESSAGE = "select * from errormessage where Error_Code=";

	public static final String SELECT_LIST_AS1 = "select * from autnum where Start_Autnum <=";
	public static final String SELECT_LIST_AS2 = " and ";
	public static final String SELECT_LIST_AS3 = "<= End_Autnum ";

	public static final String SELECT_JOIN_LIST_LINK = "select * from link join m2m_link on m2m_link.linkId= link.linkId and m2m_link.Handle=";
	public static final String SELECT_JOIN_LIST_JOINRIRENTITY = "select * from RIREntity join m2m_rirentity on m2m_rirentity.rirentityHandle=RIREntity.Handle and  m2m_rirentity.Handle=";
	public static final String SELECT_JOIN_LIST_PHONE = "select * from phones join m2m_phones on m2m_phones.phoneId=phones.phonesId and m2m_phones.Handle=";
	public static final String SELECT_JOIN_LIST_POSTALADDRESS = "select * from postaladdress join m2m_postaladress on m2m_postaladress.postalAddressId=postalAddress.postalAddressId and m2m_postaladress.Handle=";
	public static final String SELECT_JOIN_LIST_DELEGATIONKEYS = "select * from delegationKeys join m2m_delegationKeys on m2m_delegationKeys.delegationKeyId= delegationKeys.delegationKeysId and  m2m_delegationKeys.Handle=";
	public static final String SELECT_JOIN_LIST_NOTICES = "select * from notices join m2m_notices on m2m_notices.noticesId=notices.noticesId and  m2m_notices.Handle=";
	public static final String SELECT_JOIN_LIST_REMARKS = "select * from remarks join m2m_remarks on m2m_remarks.remarksId=remarks.remarksId and  m2m_remarks.Handle=";
	public static final String SELECT_JOIN_LIST_EVENTS = "select * from events join m2m_events on m2m_events.eventsId=events.eventsId and m2m_events.Handle=";
	public static final String SELECT_JOIN_LIST_PUBLICIDS = "select * from publicIds join m2m_publicIds on m2m_publicIds.identifier=publicIds.identifier and  m2m_publicIds.Handle=";
	public static final String SELECT_JOIN_LIST_SECUREDNS = "select if(Zone_Signed=0,'false','true') as Zone_Signed, if(Delegation_Signed=0,'false','true') as Delegation_Signed, Max_SigLife, secureDNS.secureDNSID, Handle, m2m_secureDNS.SecureDNSID, type from secureDNS join m2m_secureDNS on m2m_secureDNS.secureDNSID=secureDNS.secureDNSID and  m2m_secureDNS.Handle=";
	public static final String SELECT_JOIN_LIST_DSDATA = "select * from dsData join m2m_dsData on m2m_dsData.dsDataID=dsData.dsDataID and  m2m_dsData.Handle=";
	public static final String SELECT_JOIN_LIST_KEYDATA = "select * from keyData join m2m_keyData on m2m_keyData.keyDataID=keyData.keyDataID and  m2m_keyData.Handle=";

	public static final String SELECT_JOIN_LIST_REGISTRAR = "select * from registrar join m2m_registrar on m2m_registrar.registrarHandle=registrar.Handle and  m2m_registrar.Handle=";
	public static final String SELECT_JOIN_LIST_JOINNAMESERVER = "select * from nameserver join m2m_nameserver on m2m_nameserver.nameserverHandle=nameserver.Handle and m2m_nameserver.Handle=";
	public static final String SELECT_JOIN_LIST_VARIANTS = "select * from variants join m2m_variants on m2m_variants.variantsId=variants.variantsId and m2m_variants.Handle=";
	public static final String SELECT_JOIN_LIST_JOINDNRENTITY = "select * from dnrentity join m2m_dnrentity on m2m_dnrentity.dnrentityHandle=dnrentity.Handle and m2m_dnrentity.Handle=";

	public static final String SELECT_LIST_LINK = "select * from link where linkId=";
	public static final String SELECT_LIST_PHONE = "select * from phones where phonesId=";
	public static final String SELECT_LIST_POSTALADDRESS = "select * from postaladdress where postalAddressId=";
	public static final String SELECT_LIST_VARIANTS = "select * from variants where variantsId=";
	public static final String SELECT_LIST_SECUREDNS = "select * from secureDNS where secureDNSID=";
	public static final String SELECT_LIST_DSDATA = "select * from dsData where dsDataID=";
	public static final String SELECT_LIST_KEYDATA = "select * from keyData where keyDataID=";
	public static final String SELECT_LIST_DELEGATIONKEYS = "select * from delegationKeys where delegationKeysId=";
	public static final String SELECT_LIST_NOTICES = "select * from notices where noticesId=";
	public static final String SELECT_LIST_JOIN_REGISTRAR = "select * from registrar where Handle=";
	public static final String SELECT_LIST_REGISTRAR = "select * from registrar where Entity_Names=";

	public static final String SELECT_LIST_REMARKS = "select * from remarks where remarksId=";
	public static final String SELECT_LIST_EVENTS = "select * from events where eventsId=";
	public static final String SELECT_HELP = "select * from notices where noticesId=";

	public static final String ARRAYFILEDPRX = "$array$";
	public static final String JOINFILEDPRX = "$join$";
	public static final String EXTENDPRX = "$x$";
	public static final String MULTIPRX = "$mul$";

	public static final String MULTIPRXIP = "$mul$" + "IP";
	public static final String MULTIPRXDMOAIN = "$mul$" + DMOAIN;
	public static final String MULTIPRXENTITY = "$mul$" + ENTITY;
	public static final String MULTIPRXAUTNUM = "$mul$" + AUTNUM;
	public static final String MULTIPRXNAMESERVER = "$mul$" + "nameServer";
	public static final String MULTIPRXLINK = "$mul$" + LINK;
	public static final String MULTIPRXPHONES = "$mul$" + PHONES;
	public static final String MULTIPRXPOSTALASSDESS = "$mul$"
			+ "postalAddress";
	public static final String MULTIPRXVARIANTS = "$mul$" + VARIANTS;
	public static final String MULTIPRXDELEGATIONKEY = "$mul$"
			+ "delegationKeys";
	public static final String MULTIPRXNOTICES = "$mul$" + "notices";
	public static final String MULTIPRXREGISTRAR = "$mul$" + "registrar";
	public static final String MULTIPRXREMARKS = "$mul$" + REMARKS;
	public static final String MULTIPRXEVENTS = "$mul$" + VARIANTS;

	public static final String JOINENTITESFILED = JOINFILEDPRX + "entities";
	public static final String JOINLINKFILED = JOINFILEDPRX + "links";
	public static final String JOINPHONFILED = JOINFILEDPRX + "phones";
	public static final String JOINPOSTATLADDRESSFILED = JOINFILEDPRX
			+ "postalAddress";
	public static final String JOINVARIANTS = JOINFILEDPRX + "variants";
	public static final String JOINNAMESERVER = JOINFILEDPRX + "nameServers";
	public static final String JOINNANOTICES = JOINFILEDPRX + "notices";
	public static final String JOINREMARKS = JOINFILEDPRX + "remarks";
	public static final String JOINEVENTS = JOINFILEDPRX + "events";
	public static final String JOINPUBLICIDS = JOINFILEDPRX + "publicIds";
	public static final String JOINSECUREDNS = JOINFILEDPRX + "secureDNS";
	public static final String JOINDSDATA = JOINFILEDPRX + "dsData";
	public static final String JOINKEYDATA = JOINFILEDPRX + "keyData";
	public static final String JOINIP = JOINFILEDPRX + "ip";
	public static final String JOINDALEGATIONKEYS = JOINFILEDPRX
			+ "delegationKeys";
	public static final List<String> JOIN_FIELDS_WITH_CAMEL_STYLE = Arrays
			.asList(new String[] { "postalAddress", "nameServers", "publicIds",
					"secureDNS", "dsData", "keyData", "delegationKeys",
					"ipAddresses", "rdapConformance", "vcardArray",
					"asEventActor",SEARCH_RESULTS_TRUNCATED_EKEY });

	public static final String VALUEARRAYPRX = "'~'";
	public static final String HANDLE = "Handle";
	public static final String LINEBREAK = "<br/>";
	public static final String IFNULL = null;
	public static final String PERMISSIONPRX = "~";
	public static final String IPPREFIX = "ipAddresses";
	public static final String IPV4PREFIX = "v4";
	public static final String IPV6PREFIX = "v6";
	public static final String IPPREFIX_NS = "ip";

	public static final String SEARCHDOMAIN = "domains";

	public static String[] IPKeyFileds = { "Handle",
			"StartHighAddress", "StartLowAddress", "EndLowAddress",
			"EndHighAddress", "Lang",JOINNANOTICES,
			"IP_Version",
			"Name", // ARRAYFILEDPRX + "Description",
			"Type", "Country", "Parent_Handle", JOINREMARKS,
			ARRAYFILEDPRX + "Status", JOINEVENTS, JOINENTITESFILED,
			JOINLINKFILED };

	public static String[] DNREntityKeyFileds = { "Handle",
			ARRAYFILEDPRX + "Entity_Names", "Lang", JOINNANOTICES,
			ARRAYFILEDPRX + "Status", ARRAYFILEDPRX + "Roles",
			JOINPOSTATLADDRESSFILED, ARRAYFILEDPRX + "Emails", JOINPHONFILED,
			JOINREMARKS, JOINLINKFILED, "Port43", JOINEVENTS,
			JOINPUBLICIDS, "Bday", "Anniversary", "Gender", "Kind",
			"Language_Tag_1", "Pref1", "Language_Tag_2", "Pref2", "Org",
			"Title", "Role", "Geo", "Key", "Tz", "Url" };

	public static String[] RIREntityKeyFileds = { "Handle",
			ARRAYFILEDPRX + "Entity_Names", "Lang", JOINNANOTICES,
			ARRAYFILEDPRX + "Roles", JOINPOSTATLADDRESSFILED,
			ARRAYFILEDPRX + "Emails", JOINPHONFILED, JOINREMARKS,
			JOINLINKFILED, JOINEVENTS, JOINPUBLICIDS, "Bday", "Anniversary",
			"Gender", "Kind", "Language_Tag_1", "Pref1", "Language_Tag_2",
			"Pref2", "Org", "Title", "Role", "Geo", "Key", "Tz", "Url" };

	public static String[] DNRDomainKeyFileds = { "Handle", "Ldh_Name",
			"Unicode_Name", "Lang", JOINNANOTICES, JOINVARIANTS,
			ARRAYFILEDPRX + "Status",
			JOINNAMESERVER, // JOINDALEGATIONKEYS,
			"Port43", JOINEVENTS, JOINENTITESFILED,
			JOINLINKFILED, JOINREMARKS, JOINPUBLICIDS, JOINSECUREDNS };

	public static String[] RIRDomainKeyFileds = { "Handle", "Ldh_Name", "Lang",
			JOINNANOTICES,
			JOINNAMESERVER, // JOINDALEGATIONKEYS,
			JOINREMARKS, JOINLINKFILED, JOINEVENTS, JOINENTITESFILED,
			JOINPUBLICIDS, JOINSECUREDNS };

	public static String[] ASKeyFileds = { "Handle", "Start_Autnum",
			"End_Autnum", "Name", "Lang", JOINNANOTICES,
			// ARRAYFILEDPRX + "Description",
			"Type", ARRAYFILEDPRX + "Status", "Country", JOINREMARKS,
			JOINLINKFILED, JOINEVENTS, JOINENTITESFILED };

	public static String[] nameServerKeyFileds = { "Handle", "Ldh_Name",
			"Unicode_Name", "Lang", JOINNANOTICES, ARRAYFILEDPRX + "Status",
			ARRAYFILEDPRX + "IPV4_Addresses", ARRAYFILEDPRX + "IPV6_Addresses",
			"Port43", JOINREMARKS, JOINLINKFILED, JOINEVENTS, JOINENTITESFILED,
			JOINIP};

	public static String[] phonesKeyFileds = { ARRAYFILEDPRX + "Office",
			ARRAYFILEDPRX + "Fax", ARRAYFILEDPRX + "Mobile", "phonesId" };

	public static String[] variantsKeyFileds = { ARRAYFILEDPRX + "Relation",
			ARRAYFILEDPRX + "Variant_Names", "variantsId", "IDNTable" };
	public static String[] nsipKeyFileds = { "ip","type" };

	public static String[] ErrorMessageKeyFileds = { "Error_Code", "Title",
			"Lang", ARRAYFILEDPRX + "Description", JOINNANOTICES };

	public static String[] linkKeyFileds = { "Value", "Rel", "Href", "linkId",
			"$array$hreflang", "$array$title", "media", "type" };

	public static String[] postalAddressKeyFileds = { "Street", "Street1",
			"Street2", "City", "SP", "Postal_Code", "Country",
			"postalAddressId" };

	public static String[] registrarKeyFileds = { "Handle", "Entity_Names",
			ARRAYFILEDPRX + "Status", "Roles", JOINPOSTATLADDRESSFILED,
			ARRAYFILEDPRX + "Emails", JOINPHONFILED, JOINREMARKS,
			JOINLINKFILED, "Port43", JOINEVENTS };

	public static String[] noticesKeyFileds = { "Title",
			ARRAYFILEDPRX + "Description", "noticesId", JOINLINKFILED };

	public static String[] publicIdsKeyFileds = { "type", "identifier" };

	public static String[] secureDNSKeyFileds = { "Zone_Signed",
			"Delegation_Signed", "Max_SigLife", "SecureDNSID", JOINDSDATA,
			JOINKEYDATA };

	public static String[] dsDataKeyFileds = { "Key_Tag", "Algorithm",
			"Digest", "Digest_Type", "DsDataID", JOINEVENTS };

	public static String[] keyDataKeyFileds = { "Flags", "Protocol",
			"Public_Key", "Algorithm", "KeyDataID", JOINEVENTS };

	public static String[] remarksKeyFileds = { "Title",
			ARRAYFILEDPRX + "Description", "remarksId", JOINLINKFILED };

	public static String[] eventsKeyFileds = { "Event_Action", "Event_Actor",
			"Event_Date", "eventsId" };

	public static String[] helpKeyFileds = { JOINNANOTICES };

	public static String[] queryTypes = { "autnum", "domain", "dsData",
			"entity", "events", "help", "ip", "keyData", "links", "nameserver",
			"notices", "phones", "postalAddress", "registrar", "remarks",
			"secureDNS", "variants", };

	public static String[] extendColumnTableTypes = { "autnum", "dnrdomain",
			"dnrentity", "dsData", "errormessage", "events", "help", "ip",
			"keyData", "link", "nameserver", "notices","nsip", "phones",
			"postaladdress", "publicIds", "registrar", "remarks", "rirdomain",
			"rirentity", "secureDNS", "variants" };

	public static String[][] keyFiledsSet = { ASKeyFileds, DNRDomainKeyFileds,
			DNREntityKeyFileds, dsDataKeyFileds, ErrorMessageKeyFileds,
			eventsKeyFileds, helpKeyFileds, IPKeyFileds, keyDataKeyFileds,
			linkKeyFileds, nameServerKeyFileds, noticesKeyFileds,nsipKeyFileds,
			phonesKeyFileds, postalAddressKeyFileds, publicIdsKeyFileds,
			registrarKeyFileds, remarksKeyFileds, RIRDomainKeyFileds,
			RIREntityKeyFileds, secureDNSKeyFileds, variantsKeyFileds};

	public static final String UNPROCESSABLEERRORCODE = "422";

	public static final String ERRORCODE = "404";
	public static final String ERRORTITLE = "Error Message";
	public static final String[] ERRORDESCRIPTION = { "NOT FOUND" };

	public static final String COMMENDRRORCODE = "400";
	public static final String OMMENDERRORTITLE = "Error Message";
	public static final String[] OMMENDERRORDESCRIPTION = { "BAD REQUEST" };

	public static final String UNCOMMENDRRORCODE = "4145";
	public static final String UNOMMENDERRORTITLE = "Error Message";
	public static final String[] UNOMMENDERRORDESCRIPTION = { "UNKNOWN_COMMAND" };

	public static final String RATELIMITECODE = "429";
	public static final String RATELIMITEERRORTITLE = "Error Message";
	public static final String[] RATELIMITEERRORDESCRIPTION = { "RATE LIMIT" };

	public static final String ADDCOLUMN1 = "alter table ";
	public static final String ADDCOLUMN2 = " add column ";
	public static final String ADDCOLUMN3 = " varchar(";
	public static final String ADDCOLUMN4 = ")  default '' ";

	public static final String PERMISSION = "permissions";
	public static final String ADDCOLUMNNAMEPERMISSION1 = "insert into permissions (tableName,columnName,columnLength) values (";
	public static final String ADDCOLUMNNAMEPERMISSION2 = "',";
	public static final String ADDCOLUMNNAMEPERMISSION3 = ")";
	public static final String POINT = "'";

	public static final String LIST_COLUMNINFO = "select columnName,columnLength from permissions where tableName=? and columnName like '$x$%'";
	public static final String SELECT_LIST_COLUMNNAME = "select tableName,columnName from permissions where tableName=? and columnName like '$x$%'";

	public static final String UPDATE_COLUMNINFO1 = "alter table ";
	public static final String UPDATE_COLUMNINFO2 = " change ";

	public static final String UPDATE_COLUMNINFOERMISSION = "update permissions set columnName=? ,columnLength=? where tableName=? and columnName=?";

	public static final String DELETE_COLUMNINFO1 = "alter table ";
	public static final String DELETE_COLUMNINFO2 = " drop column ";

	public static final String DELETE_COLUMNINFOERMISSION1 = "delete from permissions  where columnName='";
	public static final String DELETE_COLUMNINFOERMISSION2 = "' and tableName='";

	public static final String COLUMNNAME = "columnName";
	public static final String COLUMNLENGTH = "columnLength";
	public static final String ANONYMOUS = "anonymous";
	public static final String AUTHENTICATED = "authenticated";
	public static final String ROOT = "root";

	public static final String SELECT_COLUMNINFOERMISSION = "select * from permissions where tableName=?";
	public static final String UPDATE_PERMISSION = "update permissions set anonymous=?,authenticated=?,root=? where tableName=? and columnName=?  ";

	public static final String SELECT_REDIRECT = "select * from ";
	public static final String DELETE_REDIRECT1 = "delete from ";
	public static final String DELETE_REDIRECT2 = " where id=?";

	public static final String UPDATE_DOMAIN_REDIRECTION = "update domain_redirect set redirectType=";

	public static final String UPDATE_REDIRECTION1 = " ,redirectURL=";
	public static final String UPDATE_REDIRECTION2 = " where id=";

	public static final String UPDATE_AUTNUM_REDIRECTION1 = " update autnum_redirect set startNumber= ";
	public static final String UPDATE_AUTNUM_REDIRECTION2 = " ,endNumber= ";

	public static final String UPDATE_IP_REDIRECTION1 = " update ip_redirect set StartHighAddress= ";
	public static final String UPDATE_IP_REDIRECTION2 = " ,EndHighAddress= ";
	public static final String UPDATE_IP_REDIRECTION3 = " ,StartLowAddress= ";
	public static final String UPDATE_IP_REDIRECTION4 = " ,EndLowAddress= ";

	public static final String INSERT_DOMAIN_REDIRECTION = "insert into domain_redirect (redirectType,redirectURL) values(";
	public static final String INSERT_IP_REDIRECTION = "insert into ip_redirect (StartHighAddress,EndHighAddress,StartLowAddress,EndLowAddress,redirectURL) values(";
	public static final String INSERT_AUTNUM_REDIRECTION = "insert into autnum_redirect (startNumber,endNumber,redirectURL) values(";

	public static final String ISNULL_DOMAIN_REDIRECT = "select * from domain_redirect where redirectType=? and redirectURL=?";

	public static final String ISNULL_IP_REDIRECT = "select * from ip_redirect where StartHighAddress=? and EndHighAddress=?"
			+ " and StartLowAddress=? and StartLowAddress=? and redirectURL=?";

	public static final String ISNULL_AUTNUM_REDIRECT = "select * from autnum_redirect where  startNumber=? and endNumber=? and redirectURL=? ";

	public static final String INSERT_IP_REDIRECT1 = "insert into ";
	public static final String INSERT_IP_REDIRECT2 = " (startNumber,endNumber,redirectURL) values(";

	public static final String SELECT_URL_DOAMIN_REDIRECTION = "select redirectURL from domain_redirect where redirectType=";

	public static final String SELECT_URL_AUTNUM_EDIRECTION1 = "select redirectURL from autnum_redirect where startNumber <=";
	public static final String SELECT_URL_AUTNUM_EDIRECTION2 = " and endNumber >= ";

	public static final String SELECT_URL_IPV4_REDIRECTION1 = "select redirectURL from ip_redirect where StartLowAddress <=";
	public static final String SELECT_URL_IPV4_REDIRECTION2 = " and ";
	public static final String SELECT_URL_IPV4_REDIRECTION3 = " <= EndLowAddress";

	public static final String SELECT_URL_IPV6_REDIRECTION1 = "select redirectURL from ip_redirect where (StartHighAddress <";
	public static final String SELECT_URL_IPV6_REDIRECTION2 = " or (StartHighAddress = ";
	public static final String SELECT_URL_IPV6_REDIRECTION3 = " && StartLowAddress <= ";
	public static final String SELECT_URL_IPV6_REDIRECTION4 = " )) and (EndHighAddress >";
	public static final String SELECT_URL_IPV6_REDIRECTION5 = " or (EndhighAddress = ";
	public static final String SELECT_URL_IPV6_REDIRECTION6 = " and EndLowAddress >= ";
	public static final String SELECT_URL_IPV6_REDIRECTION7 = " )) ";

	public static final String SELECT_PERMISSION = "select * from permissions where tableName = ?";

	public static final String SELECT_PERMISSION_ISNULL = "select columnName from permissions where tableName = ? and columnName=?";

	public static final Map<String, Long> queryRemoteIPMap = new HashMap<String, Long>();

	/**
	 * Generated to store a collection of fields
	 * 
	 * @param tableName
	 * @return List
	 */
	public static List<String> getKeyFileds(String tableName) {
		List<String> keyList = new ArrayList<String>();
		String[] keyFileds = null;
		int index = Arrays.binarySearch(extendColumnTableTypes, tableName);
		keyFileds = keyFiledsSet[index];
		for (int i = 0; i < keyFileds.length; i++) {
			keyList.add(keyFileds[i]);
		}
		return keyList;
	}

	/**
	 * Chinese unicode string is converted to Chinese
	 * 
	 * @param url
	 * @return ChineseUrl
	 * @throws UnsupportedEncodingException
	 */
	public static String toChineseUrl(String url)
			throws UnsupportedEncodingException {
		// %E4%E5
		String parra = "";
		java.util.List<Byte> values = new ArrayList<Byte>();
		boolean flag = true;
		for (int i = 0; i < url.length(); i++) {
			Character str3 = url.charAt(i);
			if (str3.equals('%')) {
				values.add((byte) Integer.parseInt(
						new Character(url.charAt(++i)).toString()
								+ new Character(url.charAt(++i)).toString(), 16));
				flag = false;

			} else {
				if (!flag) {
					byte[] valueByte = new byte[values.size()];
					for (int index = 0; index < valueByte.length; index++) {
						valueByte[index] = values.get(index);
					}
					parra += new String(valueByte, "utf-8") + str3.toString();
				} else {
					parra += str3.toString();

				}
				flag = true;
				values = new ArrayList<Byte>();
			}
		}
		if (!flag) {
			byte[] valueByte = new byte[values.size()];
			for (int index = 0; index < valueByte.length; index++) {
				valueByte[index] = values.get(index);
			}
			parra += new String(valueByte, "utf-8");
		}
		return parra;
	}

	/**
	 * Changes will be part of the data into the VCard style
	 * 
	 * @param map
	 * @return map collection
	 */
	public static Map<String, Object> toVCard(Map<String, Object> map) {
		List<Object> Resultlist = new ArrayList<Object>();
		List<List<Object>> list = new ArrayList<List<Object>>();
		Object entityNames = map.get(getDisplayKeyName("Entity_Names"));
		Object Bday = map.get(getDisplayKeyName("Bday"));
		Object Anniversary = map.get(getDisplayKeyName("Anniversary"));
		Object Gender = map.get(getDisplayKeyName("Gender"));
		Object Kind = map.get(getDisplayKeyName("Kind"));
		Object Language_Tag_1 = map.get(getDisplayKeyName("Language_Tag_1"));
		Object Pref1 = map.get(getDisplayKeyName("Pref1"));
		Object Language_Tag_2 = map.get(getDisplayKeyName("Language_Tag_2"));
		Object Pref2 = map.get(getDisplayKeyName("Pref2"));
		Object Org = map.get(getDisplayKeyName("Org"));
		Object Title = map.get(getDisplayKeyName("Title"));
		Object Role = map.get(getDisplayKeyName("Role"));
		Object postalAddress = map.get("postalAddress");
		Object emails = map.get(getDisplayKeyName("Emails"));
		Object phones = map.get(getDisplayKeyName("phones"));
		Object Geo = map.get(getDisplayKeyName("Geo"));
		Object Key = map.get(getDisplayKeyName("Key"));
		Object Tz = map.get(getDisplayKeyName("Tz"));
		Object Url = map.get(getDisplayKeyName("Url"));

		List<Object> firstNameList = new ArrayList<Object>();
		firstNameList.add("version");
		firstNameList.add("{}");
		firstNameList.add("text");
		firstNameList.add("4.0");
		list.add(firstNameList);
		if (entityNames != null) {
			if (isArray(entityNames)) {
				String[] namesArray = parseStringArray(entityNames);
				for (String names : namesArray) {
					List<Object> nameList = new ArrayList<Object>();
					nameList.add("fn");
					nameList.add("{}");
					nameList.add("text");
					nameList.add(names);
					list.add(nameList);
				}
			} else {
				List<Object> nameList = new ArrayList<Object>();
				nameList.add("fn");
				nameList.add("{}");
				nameList.add("text");
				nameList.add(entityNames.toString());
				list.add(nameList);
			}
			map.remove(getDisplayKeyName("Entity_Names"));
		}

		if (Bday != null) {
			if (isArray(Bday)) {
				String[] BdayArray = parseStringArray(Bday);
				for (String BdayEle : BdayArray) {
					List<Object> BdayList = new ArrayList<Object>();
					BdayList.add("bday");
					BdayList.add("{}");
					BdayList.add("date-and-or-time");
					BdayList.add(BdayEle);
					list.add(BdayList);
				}
			} else {
				List<Object> BdayList = new ArrayList<Object>();
				BdayList.add("bday");
				BdayList.add("{}");
				BdayList.add("date-and-or-time");
				BdayList.add(Bday.toString());
				list.add(BdayList);
			}
			map.remove(getDisplayKeyName("Bday"));
		}

		if (Anniversary != null) {
			if (isArray(Anniversary)) {
				String[] AnniversaryArray = parseStringArray(Anniversary);
				for (String AnniversaryEle : AnniversaryArray) {
					List<Object> AnniversaryList = new ArrayList<Object>();
					AnniversaryList.add("anniversary");
					AnniversaryList.add("{}");
					AnniversaryList.add("date-and-or-time");
					AnniversaryList.add(AnniversaryEle);
					list.add(AnniversaryList);
				}
			} else {
				List<Object> AnniversaryList = new ArrayList<Object>();
				AnniversaryList.add("anniversary");
				AnniversaryList.add("{}");
				AnniversaryList.add("date-and-or-time");
				AnniversaryList.add(Anniversary.toString());
				list.add(AnniversaryList);
			}
			map.remove(getDisplayKeyName("Anniversary"));
		}

		if (Gender != null) {
			if (isArray(Gender)) {
				String[] GenderArray = parseStringArray(Gender);
				for (String GenderEle : GenderArray) {
					List<Object> GenderList = new ArrayList<Object>();
					GenderList.add("gender");
					GenderList.add("{}");
					GenderList.add("text");
					GenderList.add(GenderEle);
					list.add(GenderList);
				}
			} else {
				List<Object> GenderList = new ArrayList<Object>();
				GenderList.add("gender");
				GenderList.add("{}");
				GenderList.add("text");
				GenderList.add(Gender.toString());
				list.add(GenderList);
			}
			map.remove(getDisplayKeyName("Gender"));
		}

		if (Kind != null) {
			if (isArray(Kind)) {
				String[] KindArray = parseStringArray(Kind);
				for (String KindEle : KindArray) {
					List<Object> KindList = new ArrayList<Object>();
					KindList.add("kind");
					KindList.add("{}");
					KindList.add("text");
					KindList.add(KindEle);
					list.add(KindList);
				}
			} else {
				List<Object> KindList = new ArrayList<Object>();
				KindList.add("kind");
				KindList.add("{}");
				KindList.add("text");
				KindList.add(Kind.toString());
				list.add(KindList);
			}
			map.remove(getDisplayKeyName("Kind"));
		}

		if ((Language_Tag_1 != null) && (Pref1 != null)) {
			List<Object> LanguageTagList = new ArrayList<Object>();
			LanguageTagList.add("lang");
			LanguageTagList.add("{\"pref\":" + "\"" + (String) Pref1 + "\""
					+ "}");
			LanguageTagList.add("language-tag");
			LanguageTagList.add((String) Language_Tag_1);
			list.add(LanguageTagList);
			map.remove(getDisplayKeyName("Language_Tag_1"));
			map.remove(getDisplayKeyName("Pref1"));
		}

		if ((Language_Tag_2 != null) && (Pref2 != null)) {
			List<Object> LanguageTagList = new ArrayList<Object>();
			LanguageTagList.add("lang");
			LanguageTagList.add("{\"pref\":" + "\"" + (String) Pref2 + "\""
					+ "}");
			LanguageTagList.add("language-tag");
			LanguageTagList.add((String) Language_Tag_2);
			list.add(LanguageTagList);
			map.remove(getDisplayKeyName("Language_Tag_2"));
			map.remove(getDisplayKeyName("Pref2"));
		}

		if (Org != null) {
			List<Object> OrgList = new ArrayList<Object>();
			OrgList.add("org");
			OrgList.add("{\"type\":\"work\"}");
			OrgList.add("text");
			OrgList.add((String) Org);
			list.add(OrgList);
			map.remove(getDisplayKeyName("Org"));
		}

		if (Title != null) {
			List<Object> TitleList = new ArrayList<Object>();
			TitleList.add("title");
			TitleList.add("{}");
			TitleList.add("text");
			TitleList.add((String) Title);
			list.add(TitleList);
			map.remove(getDisplayKeyName("Title"));
		}

		if (Role != null) {
			List<Object> RoleList = new ArrayList<Object>();
			RoleList.add("role");
			RoleList.add("{}");
			RoleList.add("text");
			RoleList.add((String) Role);
			list.add(RoleList);
			map.remove(getDisplayKeyName("Role"));
		}

		if (postalAddress != null) {
			if (postalAddress instanceof Map) {
				List<Object> nameList = new ArrayList<Object>();
				nameList.add("adr");
				nameList.add("{\"type\":\"work\"}");
				nameList.add("text");

				List<Object> addressList = new ArrayList<Object>();
				addressList.add("");
				String keyName = "";
				String element = "";
				String result = "";
				
				
				keyName = getDisplayKeyName("Street1");
				Object elementObj = ((Map) postalAddress).get(keyName);
				if(null != elementObj){
					element = ((Map) postalAddress).get(keyName).toString();
					result = result + element;
					result = result + (String) ",";
				}
				keyName = getDisplayKeyName("Street2");
				elementObj = ((Map) postalAddress).get(keyName);
				if(null != elementObj){
					result = result + element;
					addressList.add(result);
				}

				appendVcardInfo("Street",postalAddress, addressList);
				appendVcardInfo("City",postalAddress, addressList);
				appendVcardInfo("SP",postalAddress, addressList);
				appendVcardInfo("Postal_Code",postalAddress, addressList);
				appendVcardInfo("Country",postalAddress, addressList);

				nameList.add(addressList);
				list.add(nameList);
				map.remove("postalAddress");
			} else if (postalAddress instanceof Object[]) {
				for (Object postalAddressObject : ((Object[]) postalAddress)) {
					List<Object> nameList = new ArrayList<Object>();
					nameList.add("adr");
					nameList.add("{\"type\":\"work\"}");
					nameList.add("text");

					List<Object> addressList = new ArrayList<Object>();
					addressList.add("");
					String keyName = "";
					String element = "";
					String result = "";
					keyName = getDisplayKeyName("Street1");
					
					Object elementObj = ((Map) postalAddress).get(keyName);
					if(null != elementObj){
						element = ((Map) postalAddress).get(keyName).toString();
						result = result + element;
						result = result + (String) ",";
					}
					keyName = getDisplayKeyName("Street2");
					elementObj = ((Map) postalAddress).get(keyName);
					if(null != elementObj){
						result = result + element;
						addressList.add(result);
					}

					appendVcardInfo("Street",postalAddress, addressList);
					appendVcardInfo("City",postalAddress, addressList);
					appendVcardInfo("SP",postalAddress, addressList);
					appendVcardInfo("Postal_Code",postalAddress, addressList);
					appendVcardInfo("Country",postalAddress, addressList);
					
					nameList.add(addressList);
					list.add(nameList);
				}
				map.remove(getDisplayKeyName("postal_Address"));
			}
		}
		;
		if (emails != null) {
			String[] namesArray = parseStringArray(emails);// (String[]) emails;
			for (String names : namesArray) {
				List<Object> nameList = new ArrayList<Object>();
				nameList.add("email");
				nameList.add("{}");
				nameList.add("text");
				nameList.add(names);
				list.add(nameList);
			}
			map.remove(getDisplayKeyName("Emails"));
		}
		;
		if (phones != null) {
			if (phones instanceof Map) {
				Set<String> key = ((Map) phones).keySet();
				List<Object> nameList = new ArrayList<Object>();
				for (String name : key) {
					if (isNotEntityField(name)) {
						continue;
					}
					Object values = ((Map) phones).get(name);
					if (isArray(values)) {
						String typeName = "";
						if (name.equals(getDisplayKeyName("Office"))) {
							typeName = "{\"type\":\"work\"}";
						} else if (name.equals(getDisplayKeyName("Fax"))) {
							typeName = "{\"type\":\"fax\"}";
						} else if (name.equals(getDisplayKeyName("Mobile"))) {
							typeName = "{\"type\":\"cell\"}";
						}
						String[] valuesArray = parseStringArray(values);
						for (String valueName : valuesArray) {
							List<Object> nameListArray = new ArrayList<Object>();
							nameListArray.add("tel");
							nameListArray.add(typeName);
							nameListArray.add("uri");
							nameListArray.add(valueName);
							list.add(nameListArray);
						}

						continue;
					}
					nameList.add("tel");
					nameList.add("{}");
					nameList.add("uri");
					nameList.add(values.toString());
					list.add(nameList);
				}

			} else if (phones instanceof Object[]) {
				for (Object phonesObject : ((Object[]) phones)) {
					Set<String> key = ((Map) phonesObject).keySet();
					List<Object> nameList = new ArrayList<Object>();
					for (String name : key) {
						if (isNotEntityField(name)) {
							continue;
						}
						Object values = ((Map) phonesObject).get(name);
						if (isArray(values)) {
							String typeName = "";
							if (name.equals(getDisplayKeyName("Office"))) {
								typeName = "{\"type\":\"work\"}";
							} else if (name.equals(getDisplayKeyName("Fax"))) {
								typeName = "{\"type\":\"fax\"}";
							} else if (name.equals(getDisplayKeyName("Mobile"))) {
								typeName = "{\"type\":\"cell\"}";
							}
							for (String valueName : (String[]) values) {
								List<Object> nameListArray = new ArrayList<Object>();
								nameListArray.add("tel");
								nameListArray.add(typeName);
								nameListArray.add("uri");
								nameListArray.add(valueName);
								list.add(nameListArray);
							}
							continue;
						}
						nameList.add("tel");
						nameList.add("{}");
						nameList.add("uri");
						nameList.add(values.toString());
						list.add(nameList);
					}
				}
			}
			map.remove(getDisplayKeyName("phones"));
		}

		if (Geo != null) {
			if (isArray(Geo)) {
				String[] GeoArray = parseStringArray(Geo);
				for (String GeoEle : GeoArray) {
					List<Object> GeoList = new ArrayList<Object>();
					GeoList.add("geo");
					GeoList.add("{\"type\":\"work\"}");
					GeoList.add("uri");
					GeoList.add(GeoEle);
					list.add(GeoList);
				}
			} else {
				List<Object> GeoList = new ArrayList<Object>();
				GeoList.add("geo");
				GeoList.add("{\"type\":\"work\"}");
				GeoList.add("uri");
				GeoList.add(Geo.toString());
				list.add(GeoList);
			}
			map.remove(getDisplayKeyName("Geo"));
		}

		if (Key != null) {
			if (isArray(Key)) {
				String[] KeyArray = parseStringArray(Key);
				for (String KeyEle : KeyArray) {
					List<Object> KeyList = new ArrayList<Object>();
					KeyList.add("key");
					KeyList.add("{\"type\":\"work\"}");
					KeyList.add("uri");
					KeyList.add(KeyEle);
					list.add(KeyList);
				}
			} else {
				List<Object> KeyList = new ArrayList<Object>();
				KeyList.add("key");
				KeyList.add("{\"type\":\"work\"}");
				KeyList.add("uri");
				KeyList.add(Key.toString());
				list.add(KeyList);
			}
			map.remove(getDisplayKeyName("Key"));
		}

		if (Tz != null) {
			if (isArray(Tz)) {
				String[] TzArray = parseStringArray(Tz);
				for (String TzEle : TzArray) {
					List<Object> TzList = new ArrayList<Object>();
					TzList.add("tz");
					TzList.add("{}");
					TzList.add("utc-offset");
					TzList.add(TzEle);
					list.add(TzList);
				}
			} else {
				List<Object> TzList = new ArrayList<Object>();
				TzList.add("tz");
				TzList.add("{}");
				TzList.add("utc-offset");
				TzList.add(Tz.toString());
				list.add(TzList);
			}
			map.remove(getDisplayKeyName("Tz"));
		}

		if (Url != null) {
			if (isArray(Url)) {
				String[] UrlArray = parseStringArray(Url);
				for (String UrlEle : UrlArray) {
					List<Object> UrlList = new ArrayList<Object>();
					UrlList.add("url");
					UrlList.add("{\"type\":\"home\"}");
					UrlList.add("uri");
					UrlList.add(UrlEle);
					list.add(UrlList);
				}
			} else {
				List<Object> UrlList = new ArrayList<Object>();
				UrlList.add("url");
				UrlList.add("{\"type\":\"home\"}");
				UrlList.add("uri");
				UrlList.add(Url.toString());
				list.add(UrlList);
			}
			map.remove(getDisplayKeyName("Url"));
		}
		Resultlist.add("vcard");
		Resultlist.add(list);
		map.put("vcardArray", Resultlist.toArray());
		return map;
	}

	/**
	 * append vcard info to arrayList
	 * @param key
	 * @param postalAddress
	 * @param vcardList
	 * @param result
	 */
	private static void appendVcardInfo(String key, Object postalAddress,
			List<Object> vcardList) {
		String keyName = getDisplayKeyName(key);
		Object elementObj = ((Map) postalAddress).get(keyName);
		if(null == elementObj){
			return ;
		}
		String element = elementObj.toString();
		vcardList.add(element);
	}

	/**
	 * isNotEntityField
	 * @param name
	 * @return boolean
	 */
	private static boolean isNotEntityField(String name) {
		return QUERY_JOIN_TYPE.equals(name) || QUERY_TYPE.equals(name)
				|| name.endsWith("Id");
	}

	/**
	 * is an object String[] or JSONArray
	 * @param object
	 * @return boolean
	 */
	private static boolean isArray(Object object) {
		return object instanceof String[] || object instanceof JSONArray;
	}

	/**
	 * parseStringArray to String[]
	 * @param object
	 * @return String[]
	 */
	private static String[] parseStringArray(Object object) {
		if (object instanceof JSONArray) {
			JSONArray jsonArray = (JSONArray) object;
			String[] result = new String[jsonArray.size()];
			for (int i = 0; i < jsonArray.size(); i++) {
				result[i] = (String) jsonArray.get(i);
			}
			return result;
		} else if (isArray(object)) {
			return (String[]) object;
		}
		throw new IllegalArgumentException("param is not an array");
	}

	/**
	 * getDisplayKeyName
	 * @param name
	 * @return String
	 */
	public static String getDisplayKeyName(String name) {
		return name;
	}

	/**
	 * clearFormatCookie
	 * @param request
	 * @param response
	 */
	public static void clearFormatCookie(HttpServletRequest request,
			HttpServletResponse response) {
		Cookie[] cookies = request.getCookies();

		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("Format")) {
					cookie.setMaxAge(0);
					response.addCookie(cookie);
				}
			}
		}
	}

	/**
	 * Determine what kind of role the user
	 * 
	 * @param request
	 * @return role
	 */
	public static String getUserRole(HttpServletRequest request) {
		String role = "anonymous";
		if (request.isUserInRole("authenticated")
				|| request.getSession().getAttribute("openIdUser") != null) {
			role = "authenticated";
		} else if (request.isUserInRole("root")) {
			role = "root";
		}
		return role;
	}

	/**
	 * The processing Error
	 * 
	 * @return error map collection
	 * @throws QueryException
	 */
	public static Map<String, Object> processError(String errorCode,QueryParam queryParam)
			throws QueryException {
		Map<String, Object> ErrorMessageMap = null;
		QueryService queryService = (QueryService) ContextLoader
				.getCurrentWebApplicationContext().getBean("queryService");
		ErrorMessageMap = queryService.queryError(errorCode,queryParam);
		return ErrorMessageMap;
	}

	/**
	 * decode a iso8859 string to utf-8
	 * @param iso8859Str
	 * @return String
	 * @throws UnsupportedEncodingException
	 */
	private static String decodeFromUTF8(String iso8859Str)
			throws UnsupportedEncodingException {
		if (StringUtils.isBlank(iso8859Str)) {
			return iso8859Str;
		}
		byte[] nameBytes = iso8859Str.getBytes("iso-8859-1");
		return new String(nameBytes, "UTF-8");
	}

	/**
	 * is a iso8859 string  Valid UTF8
	 * @param iso8859Str
	 * @return boolean
	 * @throws UnsupportedEncodingException
	 */
	private static boolean isValidUTF8(String iso8859Str)
			throws UnsupportedEncodingException {
		if (StringUtils.isBlank(iso8859Str)) {
			return true;
		}
		byte[] bytes = iso8859Str.getBytes("iso-8859-1");
		CharsetDecoder cs = Charset.forName("UTF-8").newDecoder();
		try {
			cs.decode(ByteBuffer.wrap(bytes));
			return true;
		} catch (CharacterCodingException e) {
			return false;
		}
	}

	/**
	 * getLowerCaseByLabel
	 * @param str
	 * @return String
	 */
	public static String getLowerCaseByLabel(String str){
		if (StringUtils.isBlank(str)) {
			return str;
		}
		String[] splits = StringUtils.split(str,".");
		StringBuffer result = new StringBuffer();
		if(str.startsWith(".")){
			str = str.replaceFirst("\\.", "");
			result.append(".");
		}
		for(String split:splits){
			split = getLowerCaseIfAllAscii(split);
			result.append(split);
			result.append(".");
		}
		String resultStr = result.toString();
		if(!str.endsWith(".") && resultStr.endsWith(".")){
			resultStr = resultStr.substring(0,resultStr.length()-1);
		}
		return resultStr;
	}
	
	/**
	 * getLowerCase If asc string
	 * @param str
	 * @return String
	 */
	public static String getLowerCaseIfAllAscii(String str){
		if(isAllASCII(str)){
			return StringUtils.lowerCase(str);
		}
		return str;
	}

	/**
	 * string is of all asc 
	 * @param input
	 * @return boolean
	 */
	private static boolean isAllASCII(String input) {
		if (StringUtils.isBlank(input)) {
			return false;
		}
		boolean isASCII = true;
		for (int i = 0; i < input.length(); i++) {
			int c = input.charAt(i);
			if (c > 0x7F) {
				isASCII = false;
				break;
			}
		}
		return isASCII;
	}
	
	/**
	 * encoded url UTF-8
	 * @param str
	 * @return String
	 * @throws UnsupportedEncodingException
	 */
	public static String urlDecode(String str) throws UnsupportedEncodingException{
		if(StringUtils.isBlank(str)){
			return str;
		}
		return URLDecoder.decode(str, "UTF-8");
	}
	
	/**
	 * escape "\\*" from queryString
	 * @param q
	 * @return String
	 */
	public static String escapeQueryChars(String q){
		if(StringUtils.isBlank(q)){
			return q;
		}
		return ClientUtils.escapeQueryChars(q).replace("\\*", "*");
	}
}
