package com.cnnic.whois.service;

import java.net.MalformedURLException;
import java.util.List;

import org.apache.solr.client.solrj.SolrQuery;
import org.apache.solr.client.solrj.SolrServerException;
import org.apache.solr.client.solrj.impl.CommonsHttpSolrServer;
import org.apache.solr.client.solrj.response.QueryResponse;

import com.cnnic.whois.bean.index.NameServerIndex;
import com.cnnic.whois.bean.index.SearchCondition;
import com.cnnic.whois.service.index.SearchResult;
import com.cnnic.whois.util.WhoisProperties;
/**
 * ns search index service
 * @author nic
 *
 */
public class NameServerIndexService {
	private static NameServerIndexService indexService = new NameServerIndexService(
			WhoisProperties.getNameServerSolrUrl());
	private CommonsHttpSolrServer server;

	public static NameServerIndexService getIndexService() {
		return indexService;
	}
	/**
	 * query ns 
	 * @param searchCondition
	 * @return search result
	 */
	public SearchResult<NameServerIndex> queryNameServers(
			SearchCondition searchCondition) {
		SolrQuery solrQuery = new SolrQuery();
		solrQuery.setQuery(searchCondition.getSearchword());
		solrQuery.setStart(searchCondition.getStart());
		solrQuery.setRows(searchCondition.getRow());
		QueryResponse queryResponse = null;
		try {
			queryResponse = server.query(solrQuery);
		} catch (SolrServerException e) {
			e.printStackTrace();
		}
		SearchResult<NameServerIndex> searchResult = new SearchResult<NameServerIndex>();
		try {
			setSearchResult(searchResult, queryResponse);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return searchResult;
	}
	/**
	 * set search result
	 * @param searchResult
	 * @param queryResponse
	 */
	private void setSearchResult(SearchResult<NameServerIndex> searchResult,
			QueryResponse queryResponse) {
		searchResult
				.setSearchTime((double) queryResponse.getElapsedTime() / 1000);
		searchResult.setTotalResults(queryResponse.getResults().getNumFound());
		List<NameServerIndex> indexes = queryResponse.getBeans(NameServerIndex.class);
		searchResult.setResultList(indexes);
	}

	public NameServerIndexService(String url) {
		try {
			server = new CommonsHttpSolrServer(url);

		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}
}