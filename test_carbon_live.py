import requests

# Test the live carbon emissions calculation
try:
    print('=== Testing Live Carbon Emissions ===\n')
    print('Formula: tCO₂e = kWh × 0.93 ÷ 1000\n')
    
    # Test the meters endpoint with live carbon calculations
    response = requests.get('http://localhost:8002/api/meters/bertha-house/latest')
    print(f'Meter Data Status: {response.status_code}')
    
    if response.status_code == 200:
        data = response.json()
        
        print('Live Meter Data:')
        print(f'  Power: {data.get("power_kw", "N/A")} kW')
        print(f'  Energy Delta: {data.get("energy_kwh_delta", "N/A")} kWh')
        print(f'  Cost Delta: R{data.get("cost_zar_delta", "N/A")}')
        
        # Check carbon emissions
        carbon_tco2e = data.get('carbon_emissions_tco2e')
        carbon_kg = data.get('carbon_emissions_kg_co2e')
        carbon_rate = data.get('carbon_emission_rate_tco2e_per_hour')
        
        if carbon_tco2e is not None:
            print(f'  ✅ Carbon Emissions: {carbon_tco2e:.6f} tCO₂e')
            print(f'  ✅ Carbon Emissions: {carbon_kg:.3f} kg CO₂e')
        else:
            print('  ❌ Carbon emissions not calculated')
            
        if carbon_rate is not None:
            print(f'  ✅ Carbon Emission Rate: {carbon_rate:.6f} tCO₂e/hour')
        else:
            print('  ❌ Carbon emission rate not calculated')
            
        # Verify the calculation
        energy = data.get('energy_kwh_delta', 0)
        power = data.get('power_kw', 0)
        
        if energy > 0:
            expected_carbon = energy * 0.93 / 1000
            if carbon_tco2e and abs(expected_carbon - carbon_tco2e) < 0.000001:
                print(f'  ✅ Formula verified: {energy} × 0.93 ÷ 1000 = {expected_carbon:.6f} tCO₂e')
            else:
                print(f'  ❌ Formula mismatch: expected {expected_carbon:.6f}, got {carbon_tco2e}')
                
        if power > 0:
            expected_rate = power * 0.93 / 1000
            if carbon_rate and abs(expected_rate - carbon_rate) < 0.000001:
                print(f'  ✅ Rate formula verified: {power} × 0.93 ÷ 1000 = {expected_rate:.6f} tCO₂e/hour')
            else:
                print(f'  ❌ Rate formula mismatch: expected {expected_rate:.6f}, got {carbon_rate}')
        
        print(f'\nData Source: {data.get("_status", {}).get("source", "unknown")}')
        print(f'Health: {data.get("_status", {}).get("health", "unknown")}')
        
    else:
        print(f'Error: {response.text}')
    
    print(f'\n=== Live Carbon Test Complete ===')
    
except Exception as e:
    print(f'Test error: {e}')
