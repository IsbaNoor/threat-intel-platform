package com.threatintel.query_service.controller;

import com.threatintel.common.dto.IOC;
import com.threatintel.query_service.service.QueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class QueryController {

    private final QueryService queryService;

    @GetMapping("/iocs/search")
    public List<IOC> searchIOCs(@RequestParam String q) {
        return queryService.searchByValue(q);
    }

    @GetMapping("/iocs/statistics")
    public String getStatistics() {
        return "Total IOCs: " + queryService.getTotalCount();
    }

    @GetMapping("/health")
    public String health() {
        return "Query Service is UP!";
    }
}
