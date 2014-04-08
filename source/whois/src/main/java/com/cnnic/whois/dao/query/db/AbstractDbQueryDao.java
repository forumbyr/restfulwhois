package com.cnnic.whois.dao.query.db;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ResultSetExtractor;

import com.cnnic.whois.bean.QueryJoinType;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.util.ColumnCache;
import com.cnnic.whois.util.PermissionCache;
import com.cnnic.whois.util.WhoisUtil;
/**
 * abs db query dao
 * @author nic
 *
 */
public abstract class AbstractDbQueryDao implements QueryDao{
	//	private static AbstractDbQueryDao queryDAO = new AbstractDbQueryDao();
	
	private JdbcTemplate jdbcTemplate;

	/**
	 * get jdbc template
	 * @return
	 */
	public JdbcTemplate getJdbcTemplate() {
		return jdbcTemplate;
	}

	@Autowired
	public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}
	/**
	 * permission cache for auth controll
	 */
	protected PermissionCache permissionCache;
	
	@Autowired
	public void setPermissionCache(PermissionCache permissionCache) {
		this.permissionCache = permissionCache;
	}
	/**
	 * column cache: for authority
	 */
	protected ColumnCache columnCache;
	@Autowired
	public void setColumnCache(ColumnCache columnCache) {
		this.columnCache = columnCache;
	}

	/**
	 * daos
	 */
	@Autowired
	protected List<AbstractDbQueryDao> dbQueryDaos;
	/**
	 * is support join type
	 * @param queryType
	 * @param queryJoinType
	 * @return
	 */
	protected abstract boolean supportJoinType(QueryType queryType,
			QueryJoinType queryJoinType);
	/**
	 * query with join table
	 * @param key
	 * @param handle
	 * @return
	 * @throws SQLException
	 */
	public abstract Object querySpecificJoinTable(String key, String handle)
			throws SQLException ;
	/**
	 * get all entity,for cache init
	 */
	@Override
	public Map<String, Object> getAll()
			throws QueryException {
		throw new UnsupportedOperationException();
	}

	/**
	 * query with sql
	 * @param sql
	 * @param keyFlieds
	 * @param keyName
	 * @return query result map
	 * @throws SQLException
	 */
	protected Map<String, Object> query(String sql,
			final List<String> keyFlieds, final String keyName)
			throws SQLException {
		
		return this.getJdbcTemplate().query(sql, new ResultSetExtractor<Map<String, Object>>() {
					@Override
					public Map<String, Object> extractData(ResultSet results) throws SQLException, DataAccessException {
						List<Map<String, Object>> list = new ArrayList<Map<String, Object>>();
						while (results.next()) {
				Map<String, Object> map = new LinkedHashMap<String, Object>();
				putQueryType(map);
				for (int i = 0; i < keyFlieds.size(); i++) {
					Object resultsInfo = null;
					String field = keyFlieds.get(i);
					if (field.startsWith(WhoisUtil.ARRAYFILEDPRX)) {
						String key = field.substring(WhoisUtil.ARRAYFILEDPRX.length());
						resultsInfo = results.getString(key);
						String[] values = null;
						if (resultsInfo != null) {
							values = resultsInfo.toString().split(WhoisUtil.VALUEARRAYPRX);
						}
						map.put(key, values);
					} else if (field.startsWith(WhoisUtil.EXTENDPRX)) {
						resultsInfo = results.getString(field);
						map.put(field.substring(WhoisUtil.EXTENDPRX.length()), resultsInfo);
					} else if (field.startsWith(WhoisUtil.JOINFILEDPRX)) {
						String fliedName = getJoinFieldName(keyName);
						String key = field.substring(WhoisUtil.JOINFILEDPRX.length());
						Object value = queryJoinTable(field,
								results.getString(fliedName));
						if (value != null)
							map.put(key, value);//map or map-list
					} else {
						preHandleNormalField(keyName, results, map, field);
						resultsInfo = results.getObject(field) == null ? "": results.getObject(field);
						map.put(field, resultsInfo);//a different format have different name;
					}
				}
				map = postHandleFields(keyName, map);
				list.add(map);
			}
			if (list.size() == 0){
				return null;
			}
			Map<String, Object> mapInfo = new LinkedHashMap<String, Object>();
			// link , remark and notice change to array
			if(keyName.equals(WhoisUtil.JOINLINKFILED)|| 
					keyName.equals(WhoisUtil.JOINNANOTICES) ||
					keyName.equals(WhoisUtil.JOINREMARKS) ||
					keyName.equals(WhoisUtil.MULTIPRXLINK ) ||
					keyName.equals(WhoisUtil.JOINENTITESFILED )||
					keyName.equals(WhoisUtil.MULTIPRXREMARKS) ||
					keyName.equals(WhoisUtil.JOINPUBLICIDS) ||
					keyName.equals(WhoisUtil.JOINDSDATA)||
					keyName.equals(WhoisUtil.JOINEVENTS)||
					keyName.equals(WhoisUtil.JOINKEYDATA)){
				mapInfo.put(keyName, list.toArray());
			}else{
				if (list.size() > 1) {
					mapInfo.put(keyName, list.toArray());
				} else {
					mapInfo = list.get(0);
				}
			}
			return mapInfo;
			}
		});
	}

	/**
	 * join filed name when query join
	 * @param keyName
	 * @return filed name
	 */
	protected String getJoinFieldName(String keyName) {
		return WhoisUtil.HANDLE;
	}

	/**
	 * post handle fields
	 * @param keyName
	 * @param map
	 * @return query result
	 * @throws SQLException
	 */
	protected Map<String, Object> postHandleFields(String keyName,
			Map<String, Object> map) throws SQLException {
		return map;
	}

	/**
	 * pre handle normal field
	 * @param keyName
	 * @param results
	 * @param map
	 * @param field
	 * @throws SQLException
	 */
	protected void preHandleNormalField(String keyName,
			ResultSet results, Map<String, Object> map, String field)
			throws SQLException {}

	/**
	 * Determine the different types of schedule and query information according
	 * to the parameters
	 * 
	 * @param key
	 * @param handle
	 * @param sql
	 * @param role
	 * @param connection
	 * @return Returns the schedule information content
	 * @throws SQLException
	 */
	public Object queryJoinTable(String key, String handle) throws SQLException {
		String keyWithoutJoinPrefix = key.substring(WhoisUtil.JOINFILEDPRX.length());
		QueryJoinType joinType = QueryJoinType.getQueryJoinType(keyWithoutJoinPrefix);
		QueryType queryType = getQueryType();
		for (AbstractDbQueryDao dbQueryDao : dbQueryDaos) {
			if (dbQueryDao.supportJoinType(queryType, joinType)) {
				Object result = dbQueryDao.querySpecificJoinTable(key, handle);
				if(result instanceof Map){
					addQueryJoinTypeEntry(joinType, result);
				}else if(result instanceof Object[]){
					for(Object obj:(Object[])result){
						addQueryJoinTypeEntry(joinType, obj);
					}
				}
				return result;
			}
		}
		return null;
	}
	
	/**
	 * add query join type to query result ,for filter columns,will be removed by format filter
	 * @param joinType
	 * @param result
	 */
	private void addQueryJoinTypeEntry(QueryJoinType joinType, Object result) {
		Map map = (Map)result;
		map.put("queryJoinType", joinType.getName());
	}

	/**
	 * query schedule information
	 * 
	 * @param key
	 * @param handle
	 * @param sql
	 * @param role
	 * @param connection
	 * @param keyFlieds
	 * @return Returns the schedule information content
	 * @throws SQLException
	 */
	public Object querySpecificJoinTable(String key, String handle, String sql, List<String> keyFlieds)
			throws SQLException {

		Map<String, Object> map = query(sql + "'" + handle + "'",
				keyFlieds, key);
		if (map != null) {
			if (null == map.get(key)) {
				return map;
			} else if (!map.isEmpty()) {
				return map.get(key);
			}
		}
		return null;
	}

	/**
	 * add add rdap mark to query result map
	 * @param map:query result map
	 * @return query result map after add rdap
	 */
	public static Map<String, Object> rdapConformance(Map<String, Object> map){
		Map result = new LinkedHashMap<String, Object>();
		Object[] conform = new Object[1];
		conform[0] = WhoisUtil.RDAPCONFORMANCE;
		result.put(WhoisUtil.RDAPCONFORMANCEKEY, conform);
		if(null != map){
			result.putAll(map);
		}
		return result;
	}
	/**
	 * get authroized key fields by role
	 * @param role
	 * @return authroized key field names list
	 */
	public List<String> getKeyFields(String role) {
		throw new UnsupportedOperationException();
	}
	
	/**
	 * get map key
	 * @return map key
	 */
	public String getMapKey() {
		throw new UnsupportedOperationException();
	}
	
	/**
	 * some entites nedd reformat value,eg:ns,entity
	 * @param query result map
	 * @return query result map after formated value
	 */
	protected Map<String, Object> formatValue(Map<String, Object> map){
		return map;
	}
	
	/**
	 * put query type to query result map,used for filter columns ,will be removed by filter
	 * @param query result map
	 */
	private void putQueryType(Map<String, Object> map){
		if(map == null){
			return;
		}
		map.put(WhoisUtil.QUERY_TYPE, getQueryType().getName());
	}
}
