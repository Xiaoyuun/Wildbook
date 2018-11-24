function inrange(min,number,max){
    if ( !isNaN(number) && (number >= min) && (number <= max) ){
        return true;
    } else {
        return false;
    };
}

function validate_coords(number_lat,number_lng) {
    if (inrange(-90,number_lat,90) && inrange(-180,number_lng,180)) {
        $("#setGPSbutton").removeAttr("disabled");
        //alert("true!");
    }
    else {
        $("#setGPSbutton").attr("disabled","disabled");
        //alert("false");
    }
    //alert("nowhere");
}
