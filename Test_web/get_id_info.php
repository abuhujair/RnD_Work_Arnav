<?php
class Id_data{
        public $rstr="";
        public $id=0;
        public $name="";
        public $age=0;
    }
    function generateRandomString($length = 1000) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[random_int(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    $name_list = array("John Wick","Alan Tuning","Grace Hopper","Marie Curie","Albert Einstien","Issac Newton","Richard Fynmen","Ramanujan","CV Raman");
    $data = new Id_data();
    $data->rstr = generateRandomString(1500);
    $data->id = rand(1000,1200);
    $data->name = $name_list[rand(1,8)];
    $data->age = rand(10,100);
    $final_Data = json_encode($data);
    echo $final_Data;
?>
