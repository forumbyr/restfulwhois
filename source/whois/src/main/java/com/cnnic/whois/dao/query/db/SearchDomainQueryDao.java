package com.cnnic.whois.dao.query.db;

import java.sql.SQLException;
import java.util.Map;

import org.springframework.stereotype.Repository;

import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.bean.index.Index;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.service.index.SearchResult;

/**
 * search domain dao
 * @author nic
 *
 */
@Repository("db.searchDomainQueryDao")
public class SearchDomainQueryDao extends AbstractSearchQueryDao {

	@Override
	public Map<String, Object> query(QueryParam param) throws QueryException {
		Map<String, Object> map = null;
		SearchResult<? extends Index> result = searchQueryExecutor.query(
				QueryType.SEARCHDOMAIN, param);
		if (result.getResultList().size() == 0) {
			return map;
		}
		try {
			Map<String, Object> domainMap = super.fuzzyQuery(result, "$mul$domains");
			if (domainMap != null) {
				map = rdapConformance(map);
				map.putAll(domainMap);
				addTruncatedParamToMap(map, result);
			}
		} catch (SQLException e) {
			e.printStackTrace();
			throw new QueryException(e);
		}
		return map;
	}

	@Override
	public QueryType getQueryType() {
		return QueryType.SEARCHDOMAIN;
	}

	@Override
	public boolean supportType(QueryType queryType) {
		return QueryType.SEARCHDOMAIN.equals(queryType);
	}
	
	@Override
	public String getMapKey() {
		return "domainSearchResults";
	}
}
