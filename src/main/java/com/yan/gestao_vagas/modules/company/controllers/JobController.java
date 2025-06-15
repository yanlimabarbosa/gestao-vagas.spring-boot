package com.yan.gestao_vagas.modules.company.controllers;

import com.yan.gestao_vagas.modules.company.dto.CreateJobDTO;
import com.yan.gestao_vagas.modules.company.entities.JobEntity;
import com.yan.gestao_vagas.modules.company.useCases.CreateJobUseCase;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/company/job")
public class JobController {
    @Autowired
    private CreateJobUseCase createJobUseCase;

    @PostMapping("/")
    @PreAuthorize("hasRole('COMPANY')")
    public ResponseEntity<Object> create(@Valid @RequestBody CreateJobDTO createJobDTO, HttpServletRequest request) {
        try {
            var companyId = request.getAttribute("company_id");
            var jobEntity = JobEntity.builder()
                    .companyId(UUID.fromString(companyId.toString()))
                    .benefits(createJobDTO.getBenefits())
                    .description(createJobDTO.getDescription())
                    .level(createJobDTO.getLevel())
                    .build();
            var result = this.createJobUseCase.execute(jobEntity);

            return ResponseEntity.ok().body(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
