package com.cnnic.whois.util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.InitialContext;
import javax.sql.DataSource;

public class ColumnCache {
	private static ColumnCache columnCache = new ColumnCache();
	private List<String> IPKeyFileds = new ArrayList<String>();
	private List<String> DNREntityKeyFileds = new ArrayList<String>();
	private List<String> RIREntityKeyFileds = new ArrayList<String>();
	private List<String> DNRDomainKeyFileds = new ArrayList<String>();
	private List<String> RIRDomainKeyFileds = new ArrayList<String>();
	private List<String> ASKeyFileds = new ArrayList<String>();
	private List<String> NameServerKeyFileds = new ArrayList<String>();
	private List<String> phonesKeyFileds = new ArrayList<String>();
	private List<String> variantsKeyFileds = new ArrayList<String>();
	private List<String> LinkKeyFileds = new ArrayList<String>();
	private List<String> postalAddressKeyFileds = new ArrayList<String>();
	private List<String> delegationKeyFileds = new ArrayList<String>();
	private List<String> registrarKeyFileds = new ArrayList<String>();
	private List<String> noticesKeyFileds = new ArrayList<String>();
	private List<String> remarksKeyFileds = new ArrayList<String>();
	private List<String> eventsKeyFileds = new ArrayList<String>();

	/**
	 * In the constructor to initialize the property value
	 */
	private ColumnCache() {
		IPKeyFileds = getKeyList(WhoisUtil.IP);
		DNREntityKeyFileds = getKeyList(WhoisUtil.DNRENTITY);
		RIREntityKeyFileds = getKeyList(WhoisUtil.RIRENTITY);
		DNRDomainKeyFileds = getKeyList(WhoisUtil.DNRDOMAIN);
		RIRDomainKeyFileds = getKeyList(WhoisUtil.RIRDOMAIN);
		ASKeyFileds = getKeyList(WhoisUtil.AUTNUM);
		NameServerKeyFileds = getKeyList(WhoisUtil.NAMESERVER);
		phonesKeyFileds = getKeyList(WhoisUtil.PHONES);
		variantsKeyFileds = getKeyList(WhoisUtil.VARIANTS);
		LinkKeyFileds = getKeyList(WhoisUtil.LINK);
		postalAddressKeyFileds = getKeyList(WhoisUtil.POSTALASSDESS);
		delegationKeyFileds = getKeyList(WhoisUtil.DELEGATIONKEYS);
		registrarKeyFileds = getKeyList(WhoisUtil.REGISTRAR);
		noticesKeyFileds = getKeyList(WhoisUtil.NOTICES);
		remarksKeyFileds = getKeyList(WhoisUtil.REMARKS);
		eventsKeyFileds = getKeyList(WhoisUtil.EVENTS);
	}

	/**
	 * Get ColumnCache objects
	 * 
	 * @return ColumnCache objects
	 */
	public static ColumnCache getColumnCache() {
		return columnCache;
	}

	/**
	 * Get IPKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getIPKeyFileds() {
		return IPKeyFileds;
	}

	/**
	 * Set IPKeyFileds
	 */
	public void setIPKeyFileds() {
		IPKeyFileds = getKeyList(WhoisUtil.IP);
	}

	/**
	 * Get DNREntityKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getDNREntityKeyFileds() {
		return DNREntityKeyFileds;
	}

	/**
	 * Set DNREntityKeyFileds
	 */
	public void setDNREntityKeyFileds() {
		DNREntityKeyFileds = getKeyList(WhoisUtil.DNRENTITY);
	}

	/**
	 * Get RIREntityKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getRIREntityKeyFileds() {
		return RIREntityKeyFileds;
	}

	/**
	 * Set RIREntityKeyFileds
	 */
	public void setRIREntityKeyFileds() {
		RIREntityKeyFileds = getKeyList(WhoisUtil.RIRENTITY);
	}

	/**
	 * Get DNRDomainKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getDNRDomainKeyFileds() {
		return DNRDomainKeyFileds;
	}

	/**
	 * Set DNRDomainKeyFileds
	 */
	public void setDNRDomainKeyFileds() {
		DNRDomainKeyFileds = getKeyList(WhoisUtil.DNRDOMAIN);
	}

	/**
	 * Get RIRDomainKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getRIRDomainKeyFileds() {
		return RIRDomainKeyFileds;
	}

	/**
	 * Set RIRDomainKeyFileds
	 * 
	 */
	public void setRIRDomainKeyFileds() {
		RIRDomainKeyFileds = getKeyList(WhoisUtil.RIRDOMAIN);
	}

	/**
	 * Get ASKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getASKeyFileds() {
		return ASKeyFileds;
	}

	/**
	 * Set ASKeyFileds
	 */
	public void setASKeyFileds() {
		ASKeyFileds = getKeyList(WhoisUtil.AUTUM);
	}

	/**
	 * Get NameServerKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getNameServerKeyFileds() {
		return NameServerKeyFileds;
	}

	/**
	 * Set NameServerKeyFileds
	 */
	public void setNameServerKeyFileds() {
		NameServerKeyFileds = getKeyList(WhoisUtil.NAMESERVER);
	}

	/**
	 * Get PhonesKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getPhonesKeyFileds() {
		return phonesKeyFileds;
	}

	/**
	 * Set PhonesKeyFileds
	 */
	public void setPhonesKeyFileds() {
		phonesKeyFileds = getKeyList(WhoisUtil.PHONES);
	}

	/**
	 * Get VariantsKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getVariantsKeyFileds() {
		return variantsKeyFileds;
	}

	/**
	 * Set VariantsKeyFileds
	 */
	public void setVariantsKeyFileds() {
		variantsKeyFileds = getKeyList(WhoisUtil.VARIANTS);
	}

	/**
	 * Get LinkKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getLinkKeyFileds() {
		return LinkKeyFileds;
	}

	/**
	 * Set LinkKeyFileds
	 */
	public void setLinkKeyFileds() {
		LinkKeyFileds = getKeyList(WhoisUtil.LINK);
	}

	/**
	 * Get PostalAddressKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getPostalAddressKeyFileds() {
		return postalAddressKeyFileds;
	}

	/**
	 * Set PostalAddressKeyFileds
	 */
	public void setPostalAddressKeyFileds() {
		postalAddressKeyFileds = getKeyList(WhoisUtil.POSTALASSDESS);
	}

	/**
	 * Get DelegationKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getDelegationKeyFileds() {
		return delegationKeyFileds;
	}

	/**
	 * Set DelegationKeyFileds
	 */
	public void setDelegationKeyFileds() {
		delegationKeyFileds = getKeyList(WhoisUtil.DELEGATIONKEYS);
	}

	/**
	 * Get RegistrarKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getRegistrarKeyFileds() {
		return registrarKeyFileds;
	}

	/**
	 * Set RegistrarKeyFileds
	 */
	public void setRegistrarKeyFileds() {
		this.registrarKeyFileds = getKeyList(WhoisUtil.REGISTRAR);
	}

	/**
	 * Get NoticesKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getNoticesKeyFileds() {
		return noticesKeyFileds;
	}

	/**
	 * Set NoticesKeyFileds
	 */
	public void setNoticesKeyFileds() {
		this.noticesKeyFileds = getKeyList(WhoisUtil.NOTICES);
	}

	/**
	 * Get RemarksKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getRemarksKeyFileds() {
		return remarksKeyFileds;
	}

	/**
	 * Set RemarksKeyFileds
	 */
	public void setRemarksKeyFileds() {
		this.remarksKeyFileds = getKeyList(WhoisUtil.REMARKS);
	}

	/**
	 * Get EventsKeyFileds
	 * 
	 * @return List
	 */
	public List<String> getEventsKeyFileds() {
		return eventsKeyFileds;
	}

	/**
	 * Set EventsKeyFileds
	 */
	public void setEventsKeyFileds() {
		this.noticesKeyFileds = getKeyList(WhoisUtil.EVENTS);
	}

	/**
	 * Generate the corresponding field collection based on a different table
	 * name
	 * 
	 * @param tableName
	 * @return List
	 */
	private List<String> getKeyList(String tableName) {
		List<String> coulumNameList = new ArrayList<String>();
		try {
			InitialContext ctx = new InitialContext();
			DataSource ds = (DataSource) ctx.lookup(WhoisUtil.JNDI_NAME);
			Connection connection = ds.getConnection();
			PreparedStatement stmt = connection
					.prepareStatement(WhoisUtil.SELECT_LIST_COLUMNNAME);
			stmt.setString(1, tableName);
			ResultSet results = stmt.executeQuery();

			coulumNameList = WhoisUtil.getKeyFileds(tableName);
			while (results.next()) {
				coulumNameList.add(results.getString("columnName"));
			}
			return coulumNameList;
		} catch (Exception e) {
			e.printStackTrace();
			throw new IllegalStateException(e.getMessage());
		}

	}

}