function [high_risk_nodes2]=high_risk1(X_duration_advertize,duration_threshold,covid_indexes,l22,l2)
high_risk_nodes3=[];
for i=1:l2
    if ismember(i,covid_indexes)
        for i11=1:l2
            for j=1:size(X_duration_advertize{i11},2)
                if (X_duration_advertize{i11}(2,j)== i)
                    if X_duration_advertize{i11}(1,j)>= duration_threshold
                        high_risk_nodes3=[ high_risk_nodes3 i11];
                    end
                end
            end
        end

    end
end
high_risk_nodes2=[];
for i=1:l2
    if ismember(i,high_risk_nodes3)
        high_risk_nodes2=[ high_risk_nodes2 i];
    elseif ismember(i,covid_indexes)
        high_risk_nodes2=[high_risk_nodes2 i];
    end
end
end