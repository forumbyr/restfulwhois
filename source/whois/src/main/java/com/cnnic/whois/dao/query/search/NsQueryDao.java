package com.cnnic.whois.dao.query.search;

import com.cnnic.whois.bean.DomainQueryParam;
import com.cnnic.whois.bean.PageBean;
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
		DomainQueryParam domainQueryParam = (DomainQueryParam) param;
		PageBean page = param.getPage();
		String q = domainQueryParam.getQ();
		String escapeQ = escapeSolrChar(q);
		String domainPuny = domainQueryParam.getDomainPuny();
		domainPuny = escapeSolrChar(domainPuny);
		String queryStr = "unicodeName:" + escapeQ;
		if(q.startsWith("xn--") || q.contains(".xn--")){//punycode part search
			queryStr = 
				"ldhName:" + domainPuny
				+ " OR " + queryStr;
		}
		SearchResult<NameServerIndex> result = query(queryStr, page);
		return result;
	}
}
