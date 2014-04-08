package com.cnnic.whois.dao.query.db;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Repository;

import com.cnnic.whois.bean.NsQueryParam;
import com.cnnic.whois.bean.QueryJoinType;
import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.util.WhoisUtil;
/**
 * ns query dao
 * @author nic
 *
 */
@Repository
public class NsQueryDao extends AbstractDbQueryDao {
	public static final String GET_ALL_NAMESREVER = "select * from nameServer ";

	public Map<String, Object> query(QueryParam param) throws QueryException {
		Map<String, Object> map = null;
		try {
			NsQueryParam nsQueryParam = (NsQueryParam) param;
			String sql = String.format(WhoisUtil.SELECT_LIST_NAMESREVER
					,nsQueryParam.getDomainPuny(), param.getQ());
			Map<String, Object> nsMap = query(sql,
					columnCache.getNameServerKeyFileds(),
					"$mul$nameServer");
			if (nsMap != null) {
				map = rdapConformance(map);
				map.putAll(nsMap);
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new QueryException(e);
		}
		return map;
	}

	@Override
	protected Map<String, Object> formatValue(Map<String, Object> map) {
		Map<String, Object> map_IP = new LinkedHashMap<String, Object>();
		Object IPAddressArray = map.get("IPV4_Addresses");
		map_IP.put(WhoisUtil.IPV4PREFIX, IPAddressArray);
		IPAddressArray = map.get("IPV6_Addresses");
		map_IP.put(WhoisUtil.IPV6PREFIX, IPAddressArray);
		map.put(WhoisUtil.IPPREFIX, map_IP);
		map.remove("IPV4_Addresses");
		map.remove("IPV6_Addresses");
		return map;
	}

	@Override
	public Map<String, Object> getAll() throws QueryException {
		Map<String, Object> map = null;
		try {
			Map<String, Object> nsMap = query(GET_ALL_NAMESREVER,
					columnCache.getNameServerKeyFileds(),
					"$mul$nameServer");
			if (nsMap != null) {
				map = rdapConformance(map);
				map.putAll(nsMap);
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new QueryException(e);
		}
		return map;
	}

	@Override
	public QueryType getQueryType() {
		return QueryType.NAMESERVER;
	}

	@Override
	public boolean supportType(QueryType queryType) {
		return QueryType.NAMESERVER.equals(queryType);
	}

	@Override
	protected boolean supportJoinType(QueryType queryType,
			QueryJoinType queryJoinType) {
		return QueryJoinType.NAMESERVER.equals(queryJoinType);
	}

	@Override
	public Object querySpecificJoinTable(String key, String handle) throws SQLException {
		return querySpecificJoinTable(key, handle,
				WhoisUtil.SELECT_JOIN_LIST_JOINNAMESERVER, columnCache.getNameServerKeyFileds());
	}

	@Override
	public List<String> getKeyFields(String role) {
		List<String> cacheFields = permissionCache
				.getNameServerKeyFileds(role);
		List<String> result = new ArrayList<String>(cacheFields);
		result.add(WhoisUtil.IPPREFIX);
		result.add(WhoisUtil.IPV4PREFIX);
		result.add(WhoisUtil.IPV6PREFIX);
		return result;
	}
}
