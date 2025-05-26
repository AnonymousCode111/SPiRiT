function [high_risk_nodes2]=DP_3T_FN(K1,ss2,covid_indexes_initial, X_duration,duration_threshold,covid_indexes,l22,l2,erased_indexes,unerased_indexes)



high_risk_nodes3=[];
for i=1:l2
    if ismember(i,covid_indexes)
        if ismember(i,covid_indexes_initial)
            [aaa,bbb]=find(covid_indexes_initial==i);
            if ismember(K1 ,ss2(:,aaa))
            else
                if ismember(i,unerased_indexes)
                    for i11=1:l2
                        for j=1:size(X_duration{i11},2)
                            if (X_duration{i11}(2,j)== i)
                                if ismember(i11,unerased_indexes)
                                    if X_duration{i11}(1,j)>= duration_threshold
                                        high_risk_nodes3=[ high_risk_nodes3 i11];                                     end
                                end
                            end
                        end
                    end
                end
            end

        else
            if ismember(i,unerased_indexes)
                for i11=1:l2
                    for j=1:size(X_duration{i11},2)
                        if (X_duration{i11}(2,j)== i)
                            if ismember(i11,unerased_indexes)
                                if X_duration{i11}(1,j)>= duration_threshold
                                    high_risk_nodes3=[ high_risk_nodes3 i11];
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    high_risk_nodes2=[];numcovid_indexes=numel(covid_indexes);
    for i=1:l2
        if ismember(i,high_risk_nodes3)
            high_risk_nodes2=[high_risk_nodes2 i];
        elseif ismember(i,covid_indexes)
            if ~ismember(i,erased_indexes)
                high_risk_nodes2=[high_risk_nodes2 i];
            end
        end
    end
end
