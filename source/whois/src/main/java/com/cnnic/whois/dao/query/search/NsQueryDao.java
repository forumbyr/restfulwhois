package com.cnnic.whois.dao.query.search;

import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.bean.index.NameServerIndex;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.service.index.SearchResult;
/**
 * ns search dao
 * @author nic
 *
 */
public class NsQueryDao extends AbstractSearchQueryDao<NameServerIndex> {

	/**
	 * construction
	 * @param url:ns solr core url
	 */
	public NsQueryDao(String url) {
		super(url);
	}

	@Override
	public QueryType getQueryType() {
		return QueryType.SEARCHNS;
	}

	@Override
	public boolean supportType(QueryType queryType) {
		return getQueryType().equals(queryType);
	}

	@Override
	public SearchResult<NameServerIndex> search(QueryParam param)
			throws QueryException {
		String q = param.getQ();
		SearchResult<NameServerIndex> result = query(q, param.getPage());
		return result;
	}
}
